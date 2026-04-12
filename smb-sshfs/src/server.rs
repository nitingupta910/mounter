//! SMB2 server that translates filesystem operations to SFTP calls.
//!
//! Handles one macOS client connection. Implements the minimal SMB2 command
//! set that mount_smbfs needs: NEGOTIATE, SESSION_SETUP, TREE_CONNECT,
//! CREATE, CLOSE, READ, WRITE, QUERY_DIRECTORY, QUERY_INFO, SET_INFO.

use crate::sftp::{DirEntry, FileAttr, SftpError, SftpSession};
use crate::smb2::*;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

// ── macOS noise filter ──────────────────────────────────────────────
// Files that macOS queries for every directory but never exist on Linux.

fn is_apple_metadata(name: &str) -> bool {
    name == ".DS_Store"
        || name == ".localized"
        || name == ".hidden"
        || name.starts_with("._")
        || name == "Icon\r"
        || name == ".Spotlight-V100"
        || name == ".Trashes"
        || name == ".fseventsd"
        || name == ".TemporaryItems"
        || name == ".com.apple.timemachine.donotpresent"
}

// ── Attr cache ──────────────────────────────────────────────────────

const CACHE_TTL_SECS: u64 = 30;
const NEG_CACHE_TTL_SECS: u64 = 60; // longer for negative since Apple metadata never exists

struct CachedAttr {
    attr: FileAttr,
    is_dir: bool,
    expires: Instant,
}

struct AttrCache {
    positive: HashMap<String, CachedAttr>,
    negative: HashMap<String, Instant>,
}

impl AttrCache {
    fn new() -> Self {
        AttrCache {
            positive: HashMap::new(),
            negative: HashMap::new(),
        }
    }

    fn get(&self, path: &str) -> Option<(&FileAttr, bool)> {
        self.positive.get(path).and_then(|c| {
            if c.expires > Instant::now() {
                Some((&c.attr, c.is_dir))
            } else {
                None
            }
        })
    }

    fn is_negative(&self, path: &str) -> bool {
        self.negative
            .get(path)
            .map(|exp| *exp > Instant::now())
            .unwrap_or(false)
    }

    fn insert(&mut self, path: String, attr: FileAttr, is_dir: bool) {
        self.negative.remove(&path);
        self.positive.insert(
            path,
            CachedAttr {
                attr,
                is_dir,
                expires: Instant::now() + std::time::Duration::from_secs(CACHE_TTL_SECS),
            },
        );
    }

    fn insert_negative(&mut self, path: String) {
        let ttl = if is_apple_metadata(path.rsplit('/').next().unwrap_or("")) {
            NEG_CACHE_TTL_SECS
        } else {
            CACHE_TTL_SECS / 2
        };
        self.negative
            .insert(path, Instant::now() + std::time::Duration::from_secs(ttl));
    }

    fn invalidate(&mut self, path: &str) {
        self.positive.remove(path);
        self.negative.remove(path);
    }

    fn insert_dir_entries(&mut self, parent: &str, entries: &[DirEntry]) {
        for e in entries {
            let child = format!("{parent}/{}", e.name);
            let is_dir = e.attrs.perm & 0o40000 != 0;
            self.insert(child, e.attrs.clone(), is_dir);
        }
    }
}

// ── Open file/dir handles ───────────────────────────────────────────

struct OpenHandle {
    sftp_handle: Option<Vec<u8>>, // None for directories
    path: String,
    is_dir: bool,
    dir_entries: Option<Vec<DirEntry>>, // cached readdir result
    dir_offset: usize,
}

// ── SMB2 Server Session ─────────────────────────────────────────────

pub struct SmbSession {
    sftp: Arc<SftpSession>,
    root_path: String,
    share_name: String,
    session_id: u64,
    tree_id: u32,
    handles: HashMap<u64, OpenHandle>,
    next_handle: u64,
    cache: AttrCache,
    auth_phase: u8,
    /// Last handle created — used for related compound requests where
    /// QUERY_INFO/CLOSE reference FileId=0xFFFFFFFF meaning "use CREATE's handle."
    last_create_handle: u64,
}

impl SmbSession {
    pub fn new(sftp: Arc<SftpSession>, root_path: String, share_name: String) -> Self {
        SmbSession {
            sftp,
            root_path,
            share_name,
            session_id: 0x0000_0001_0000_0001,
            tree_id: 1,
            handles: HashMap::new(),
            next_handle: 1,
            cache: AttrCache::new(),
            auth_phase: 0,
            last_create_handle: 0,
        }
    }

    /// Resolve FileId — handles 0xFFFFFFFFFFFFFFFF sentinel for related compounds.
    fn resolve_fid(&self, fid: u64) -> u64 {
        if fid == 0xFFFF_FFFF_FFFF_FFFF {
            self.last_create_handle
        } else {
            fid
        }
    }

    fn full_path(&self, rel: &str) -> String {
        if rel.is_empty() || rel == "\\" || rel == "/" {
            self.root_path.clone()
        } else {
            let normalized = rel.replace('\\', "/");
            let trimmed = normalized.trim_start_matches('/');
            format!("{}/{}", self.root_path, trimmed)
        }
    }

    fn alloc_handle(&mut self) -> u64 {
        let h = self.next_handle;
        self.next_handle += 1;
        h
    }

    fn stat_cached(&mut self, path: &str) -> Result<(FileAttr, bool), u32> {
        if let Some((attr, is_dir)) = self.cache.get(path) {
            return Ok((attr.clone(), is_dir));
        }
        if self.cache.is_negative(path) {
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }

        // Check macOS noise — skip SFTP for known-absent files
        let basename = path.rsplit('/').next().unwrap_or("");
        if is_apple_metadata(basename) {
            self.cache.insert_negative(path.to_string());
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }

        match self.sftp.lstat(path) {
            Ok(attr) => {
                let is_dir = attr.perm & 0o40000 != 0;
                self.cache.insert(path.to_string(), attr.clone(), is_dir);
                Ok((attr, is_dir))
            }
            Err(SftpError::Status(2, _)) => {
                self.cache.insert_negative(path.to_string());
                Err(STATUS_OBJECT_NAME_NOT_FOUND)
            }
            Err(_) => Err(STATUS_ACCESS_DENIED),
        }
    }

    // ── Command dispatch ────────────────────────────────────────────

    pub fn handle_message(&mut self, msg: &[u8]) -> Vec<u8> {
        let hdr = match Smb2Header::parse(msg) {
            Some(h) => h,
            None => return Vec::new(),
        };
        let body = &msg[SMB2_HEADER_SIZE..];

        let mut response = Vec::new();
        match hdr.command {
            SMB2_NEGOTIATE => self.handle_negotiate(&hdr, body, &mut response),
            SMB2_SESSION_SETUP => self.handle_session_setup(&hdr, body, &mut response),
            SMB2_LOGOFF => self.handle_logoff(&hdr, &mut response),
            SMB2_TREE_CONNECT => self.handle_tree_connect(&hdr, body, &mut response),
            SMB2_TREE_DISCONNECT => self.handle_tree_disconnect(&hdr, &mut response),
            SMB2_CREATE => self.handle_create(&hdr, body, &mut response),
            SMB2_CLOSE => self.handle_close(&hdr, body, &mut response),
            SMB2_READ => self.handle_read(&hdr, body, &mut response),
            SMB2_WRITE => self.handle_write(&hdr, body, &mut response),
            SMB2_QUERY_DIRECTORY => self.handle_query_directory(&hdr, body, &mut response),
            SMB2_QUERY_INFO => self.handle_query_info(&hdr, body, &mut response),
            SMB2_SET_INFO => self.handle_set_info(&hdr, body, &mut response),
            SMB2_FLUSH => self.handle_flush(&hdr, &mut response),
            SMB2_IOCTL => self.handle_ioctl(&hdr, &mut response),
            _ => {
                log::warn!("Unsupported SMB2 command: 0x{:04x}", hdr.command);
                self.error_response(&hdr, STATUS_NOT_SUPPORTED, &mut response);
            }
        }
        response
    }

    fn error_response(&self, hdr: &Smb2Header, status: u32, out: &mut Vec<u8>) {
        // 9-byte error response body
        let mut body = Vec::with_capacity(9);
        body.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
        body.push(0); // ErrorContextCount
        body.push(0); // Reserved
        body.extend_from_slice(&0u32.to_le_bytes()); // ByteCount
        body.push(0); // ErrorData (1 byte padding)
        hdr.write_response(status, &body, out);
    }

    // ── NEGOTIATE ───────────────────────────────────────────────────

    fn handle_negotiate(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        // Parse client's requested dialects to pick the best one
        let dialect_count = if body.len() >= 4 {
            read_u16_le(body, 2) as usize
        } else {
            0
        };
        // Force SMB 2.0.2 — simplest dialect, no signing needed for guest.
        // SMB 3.x requires signing which breaks unsigned guest sessions.
        let _ = dialect_count;
        let best_dialect = SMB2_DIALECT_202;
        log::info!("Negotiated dialect: 0x{:04x}", best_dialect);

        let spnego = build_spnego_negotiate_token();

        let mut resp = Vec::with_capacity(128 + spnego.len());
        resp.extend_from_slice(&65u16.to_le_bytes()); // StructureSize
        resp.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode: SIGNING_ENABLED
        resp.extend_from_slice(&best_dialect.to_le_bytes()); // DialectRevision
        resp.extend_from_slice(&0u16.to_le_bytes()); // Reserved

        // ServerGuid (16 bytes)
        resp.extend_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        resp.extend_from_slice(&7u32.to_le_bytes()); // Capabilities: DFS | LEASING | LARGE_MTU
        resp.extend_from_slice(&(8 * 1024 * 1024u32).to_le_bytes()); // MaxTransactSize: 8 MB
        resp.extend_from_slice(&(8 * 1024 * 1024u32).to_le_bytes()); // MaxReadSize: 8 MB
        resp.extend_from_slice(&(8 * 1024 * 1024u32).to_le_bytes()); // MaxWriteSize: 8 MB

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        resp.extend_from_slice(&unix_to_filetime(now).to_le_bytes()); // SystemTime
        resp.extend_from_slice(&unix_to_filetime(now).to_le_bytes()); // ServerStartTime

        // SecurityBuffer at offset 128 from start of SMB2 header (64 hdr + 64 body fields)
        resp.extend_from_slice(&128u16.to_le_bytes()); // SecurityBufferOffset
        resp.extend_from_slice(&(spnego.len() as u16).to_le_bytes()); // SecurityBufferLength
        resp.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
        resp.extend_from_slice(&spnego);

        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── SESSION_SETUP ───────────────────────────────────────────────

    fn handle_session_setup(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        self.auth_phase += 1;
        log::info!("SESSION_SETUP phase {}", self.auth_phase);

        // Extract client's security buffer (SPNEGO wrapping NTLMSSP)
        // MS-SMB2 2.2.5: SecurityBufferOffset at body[12], Length at body[14]
        let sec_offset = if body.len() >= 14 {
            read_u16_le(body, 12) as usize
        } else {
            0
        };
        let sec_length = if body.len() >= 16 {
            read_u16_le(body, 14) as usize
        } else {
            0
        };
        let sec_start = sec_offset.saturating_sub(SMB2_HEADER_SIZE);
        let sec_data = if sec_start + sec_length <= body.len() {
            &body[sec_start..sec_start + sec_length]
        } else {
            &[]
        };

        // Detect NTLMSSP message type inside SPNEGO wrapper
        let ntlmssp_type = sec_data
            .windows(12)
            .find(|w| w.starts_with(b"NTLMSSP\0"))
            .map(|w| u32::from_le_bytes([w[8], w[9], w[10], w[11]]));

        log::info!(
            "SESSION_SETUP: sec_offset={sec_offset} sec_length={sec_length} ntlmssp_type={:?}",
            ntlmssp_type
        );

        if ntlmssp_type == Some(1) {
            // Phase 1: extract client's NTLMSSP flags, build matching challenge

            // Find client's negotiate flags
            let client_flags = sec_data
                .windows(12)
                .find(|w| w.starts_with(b"NTLMSSP\0"))
                .and_then(|w| {
                    if w.len() >= 16 {
                        Some(u32::from_le_bytes([w[12], w[13], w[14], w[15]]))
                    } else {
                        None
                    }
                })
                .unwrap_or(0xe2088233);

            // Build NTLMSSP_CHALLENGE echoing client flags (except VERSION)
            let server_flags = (client_flags & !0x02000000) | 0x00020000; // remove VERSION, add TARGET_TYPE_SERVER

            let mut challenge = Vec::with_capacity(56);
            challenge.extend_from_slice(b"NTLMSSP\0");        // 0: Signature
            challenge.extend_from_slice(&2u32.to_le_bytes());  // 8: Type=CHALLENGE
            // TargetName: empty (offset=48 = end of fixed fields)
            challenge.extend_from_slice(&0u16.to_le_bytes());  // 12: TargetNameLen
            challenge.extend_from_slice(&0u16.to_le_bytes());  // 14: TargetNameMaxLen
            challenge.extend_from_slice(&48u32.to_le_bytes()); // 16: TargetNameOffset
            challenge.extend_from_slice(&server_flags.to_le_bytes()); // 20: NegotiateFlags
            // ServerChallenge (8 bytes)
            challenge.extend_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]); // 24
            // Reserved (8 bytes)
            challenge.extend_from_slice(&[0u8; 8]); // 32
            // TargetInfo: empty
            challenge.extend_from_slice(&0u16.to_le_bytes());  // 40: TargetInfoLen
            challenge.extend_from_slice(&0u16.to_le_bytes());  // 42: TargetInfoMaxLen
            challenge.extend_from_slice(&48u32.to_le_bytes()); // 44: TargetInfoOffset
            // Total: 48 bytes

            log::info!("NTLMSSP challenge: client_flags=0x{client_flags:08x} server_flags=0x{server_flags:08x}");

            // Wrap in SPNEGO negTokenResp
            let spnego = wrap_ntlmssp_in_spnego(&challenge);

            let mut resp = Vec::with_capacity(16 + spnego.len());
            resp.extend_from_slice(&9u16.to_le_bytes());
            resp.extend_from_slice(&0u16.to_le_bytes()); // SessionFlags: 0
            let sec_off = (SMB2_HEADER_SIZE + 8) as u16;
            resp.extend_from_slice(&sec_off.to_le_bytes());
            resp.extend_from_slice(&(spnego.len() as u16).to_le_bytes());
            resp.extend_from_slice(&spnego);

            let mut full_hdr = hdr.clone();
            full_hdr.session_id = self.session_id;
            full_hdr.write_response(STATUS_MORE_PROCESSING, &resp, out);

            log::info!("Sent NTLMSSP challenge in SPNEGO ({} bytes)", spnego.len());
            // Dump the SPNEGO for debugging
            log::debug!("SPNEGO challenge hex: {}", hex_dump(&spnego, 128));
        } else {
            // Phase 2 (NTLMSSP_AUTH type=3) or any follow-up: accept as guest
            let accept = spnego_accept_complete();

            let mut resp = Vec::with_capacity(16 + accept.len());
            resp.extend_from_slice(&9u16.to_le_bytes());
            resp.extend_from_slice(&1u16.to_le_bytes()); // SessionFlags: IS_GUEST
            let sec_off = (SMB2_HEADER_SIZE + 8) as u16;
            resp.extend_from_slice(&sec_off.to_le_bytes());
            resp.extend_from_slice(&(accept.len() as u16).to_le_bytes());
            resp.extend_from_slice(&accept);

            let mut full_hdr = hdr.clone();
            full_hdr.session_id = self.session_id;
            full_hdr.write_response(STATUS_SUCCESS, &resp, out);
            log::info!("Session accepted as guest (phase {})", self.auth_phase);
            self.auth_phase = 0;
        }
    }

    // ── LOGOFF ──────────────────────────────────────────────────────

    fn handle_logoff(&mut self, hdr: &Smb2Header, out: &mut Vec<u8>) {
        let mut resp = Vec::with_capacity(4);
        resp.extend_from_slice(&4u16.to_le_bytes()); // StructureSize
        resp.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── TREE_CONNECT ────────────────────────────────────────────────

    fn handle_tree_connect(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        // Accept any share name (we only have one)
        let mut resp = Vec::with_capacity(16);
        resp.extend_from_slice(&16u16.to_le_bytes()); // StructureSize
        resp.push(0x01); // ShareType: DISK
        resp.push(0); // Reserved
        resp.extend_from_slice(&0x0000_0030u32.to_le_bytes()); // ShareFlags: manual caching
        resp.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
        resp.extend_from_slice(&0x001F01FFu32.to_le_bytes()); // MaximalAccess: FILE_ALL_ACCESS

        let mut full_hdr = hdr.clone();
        full_hdr.tree_id = self.tree_id;
        full_hdr.write_response(STATUS_SUCCESS, &resp, out);
        log::info!("Tree connected: share={}", self.share_name);
    }

    // ── TREE_DISCONNECT ─────────────────────────────────────────────

    fn handle_tree_disconnect(&mut self, hdr: &Smb2Header, out: &mut Vec<u8>) {
        let mut resp = Vec::with_capacity(4);
        resp.extend_from_slice(&4u16.to_le_bytes());
        resp.extend_from_slice(&0u16.to_le_bytes());
        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── CREATE (open file/directory) ────────────────────────────────

    fn handle_create(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        if body.len() < 48 {
            self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
            return;
        }

        // MS-SMB2 2.2.13 CREATE Request body layout:
        // 0-1: StructureSize=57, 2: SecurityFlags, 3: OplockLevel
        // 4-7: ImpersonationLevel, 8-15: SmbCreateFlags, 16-23: Reserved
        let _desired_access = read_u32_le(body, 24);
        let _file_attributes = read_u32_le(body, 28);
        let _share_access = read_u32_le(body, 32);
        let create_disposition = read_u32_le(body, 36);
        let create_options = read_u32_le(body, 40);
        let name_offset = read_u16_le(body, 44) as usize;
        let name_length = read_u16_le(body, 46) as usize;

        // Extract filename (UTF-16LE, offset from start of SMB2 header)
        let name_start = name_offset.saturating_sub(SMB2_HEADER_SIZE);
        let rel_name = if name_length > 0 && name_start + name_length <= body.len() {
            from_utf16le(&body[name_start..name_start + name_length])
        } else {
            String::new()
        };

        let path = self.full_path(&rel_name);
        let want_dir = create_options & FILE_DIRECTORY_FILE != 0;

        log::debug!("CREATE: path={path} disposition={create_disposition} dir={want_dir}");

        // Handle create dispositions
        // FILE_SUPERSEDE (0) is treated as FILE_OPEN for existing files (macOS uses it for share root)
        match create_disposition {
            FILE_SUPERSEDE | FILE_OPEN | FILE_OPEN_IF => {
                match self.stat_cached(&path) {
                    Ok((attr, is_dir)) => {
                        self.respond_create_success(hdr, &path, &attr, is_dir, out);
                    }
                    Err(_) if create_disposition == FILE_OPEN_IF => {
                        // Create it
                        if want_dir {
                            if let Err(e) = self.sftp.mkdir(&path, 0o755) {
                                log::warn!("mkdir failed: {e}");
                                self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                                return;
                            }
                            self.cache.invalidate(&path);
                            match self.stat_cached(&path) {
                                Ok((attr, is_dir)) => {
                                    self.respond_create_success(hdr, &path, &attr, is_dir, out);
                                }
                                Err(s) => self.error_response(hdr, s, out),
                            }
                        } else {
                            match self
                                .sftp
                                .open(&path, crate::sftp::SSH_FXF_CREAT | 0x03, 0o644)
                            {
                                Ok(sftp_handle) => {
                                    let _ = self.sftp.close(&sftp_handle);
                                    self.cache.invalidate(&path);
                                    match self.stat_cached(&path) {
                                        Ok((attr, is_dir)) => {
                                            self.respond_create_success(
                                                hdr, &path, &attr, is_dir, out,
                                            );
                                        }
                                        Err(s) => self.error_response(hdr, s, out),
                                    }
                                }
                                Err(_) => self.error_response(hdr, STATUS_ACCESS_DENIED, out),
                            }
                        }
                    }
                    Err(s) => self.error_response(hdr, s, out),
                }
            }
            FILE_CREATE => {
                if self.stat_cached(&path).is_ok() {
                    self.error_response(hdr, STATUS_OBJECT_NAME_COLLISION, out);
                    return;
                }
                if want_dir {
                    if let Err(_) = self.sftp.mkdir(&path, 0o755) {
                        self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                        return;
                    }
                } else {
                    match self
                        .sftp
                        .open(&path, crate::sftp::SSH_FXF_CREAT | 0x1a, 0o644)
                    {
                        Ok(h) => {
                            let _ = self.sftp.close(&h);
                        }
                        Err(_) => {
                            self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                            return;
                        }
                    }
                }
                self.cache.invalidate(&path);
                match self.stat_cached(&path) {
                    Ok((attr, is_dir)) => {
                        self.respond_create_success(hdr, &path, &attr, is_dir, out);
                    }
                    Err(s) => self.error_response(hdr, s, out),
                }
            }
            FILE_OVERWRITE | FILE_OVERWRITE_IF | FILE_SUPERSEDE => {
                match self.sftp.open(
                    &path,
                    crate::sftp::SSH_FXF_CREAT | crate::sftp::SSH_FXF_TRUNC | 0x02,
                    0o644,
                ) {
                    Ok(h) => {
                        let _ = self.sftp.close(&h);
                    }
                    Err(_) => {
                        self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                        return;
                    }
                }
                self.cache.invalidate(&path);
                match self.stat_cached(&path) {
                    Ok((attr, is_dir)) => {
                        self.respond_create_success(hdr, &path, &attr, is_dir, out);
                    }
                    Err(s) => self.error_response(hdr, s, out),
                }
            }
            _ => self.error_response(hdr, STATUS_INVALID_PARAMETER, out),
        }
    }

    fn respond_create_success(
        &mut self,
        hdr: &Smb2Header,
        path: &str,
        attr: &FileAttr,
        is_dir: bool,
        out: &mut Vec<u8>,
    ) {
        let handle_id = self.alloc_handle();
        self.last_create_handle = handle_id;
        self.handles.insert(
            handle_id,
            OpenHandle {
                sftp_handle: None, // opened lazily on read/write
                path: path.to_string(),
                is_dir,
                dir_entries: None,
                dir_offset: 0,
            },
        );

        let ft_create = unix_to_filetime(attr.mtime as u64);
        let ft_access = unix_to_filetime(attr.atime as u64);
        let ft_write = unix_to_filetime(attr.mtime as u64);
        let ft_change = unix_to_filetime(attr.mtime as u64);
        let file_attrs = if is_dir {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_ARCHIVE
        };

        let mut resp = Vec::with_capacity(96);
        resp.extend_from_slice(&89u16.to_le_bytes()); // StructureSize
        resp.push(0); // OplockLevel: none
        resp.push(0); // Flags
        resp.extend_from_slice(&1u32.to_le_bytes()); // CreateAction: FILE_OPENED
        resp.extend_from_slice(&ft_create.to_le_bytes()); // CreationTime
        resp.extend_from_slice(&ft_access.to_le_bytes()); // LastAccessTime
        resp.extend_from_slice(&ft_write.to_le_bytes()); // LastWriteTime
        resp.extend_from_slice(&ft_change.to_le_bytes()); // ChangeTime
        resp.extend_from_slice(&attr.size.to_le_bytes()); // AllocationSize
        resp.extend_from_slice(&attr.size.to_le_bytes()); // EndOfFile
        resp.extend_from_slice(&file_attrs.to_le_bytes()); // FileAttributes
        resp.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
                                                     // FileId: persistent (8) + volatile (8)
        resp.extend_from_slice(&handle_id.to_le_bytes()); // FileId.Persistent
        resp.extend_from_slice(&handle_id.to_le_bytes()); // FileId.Volatile
                                                          // CreateContexts
        resp.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsOffset
        resp.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsLength
        resp.push(0); // 1-byte variable part padding (StructureSize=89 means 88 fixed + 1)

        log::debug!("CREATE response ({} bytes):{}", resp.len(), hex_dump(&resp, 128));
        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── CLOSE ───────────────────────────────────────────────────────

    fn handle_close(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        let fid = if body.len() >= 24 {
            self.resolve_fid(read_u64_le(body, 8)) // FileId.Persistent
        } else {
            0
        };

        if let Some(handle) = self.handles.remove(&fid) {
            if let Some(ref sftp_h) = handle.sftp_handle {
                let _ = self.sftp.close(sftp_h);
            }
        }

        let mut resp = Vec::with_capacity(60);
        resp.extend_from_slice(&60u16.to_le_bytes()); // StructureSize
        resp.extend_from_slice(&0u16.to_le_bytes()); // Flags
        resp.extend_from_slice(&0u32.to_le_bytes()); // Reserved
        resp.extend_from_slice(&[0u8; 48]); // Times + sizes (all zero = don't update)

        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── READ ────────────────────────────────────────────────────────

    fn handle_read(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        if body.len() < 32 {
            self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
            return;
        }
        let length = read_u32_le(body, 4);
        let offset = read_u64_le(body, 8);
        let fid = self.resolve_fid(read_u64_le(body, 16));

        let handle = match self.handles.get_mut(&fid) {
            Some(h) => h,
            None => {
                self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                return;
            }
        };

        // Lazy-open SFTP handle
        if handle.sftp_handle.is_none() {
            match self.sftp.open(&handle.path, 0x01, 0) {
                // READ
                Ok(h) => handle.sftp_handle = Some(h),
                Err(_) => {
                    self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                    return;
                }
            }
        }

        let sftp_h = handle.sftp_handle.as_ref().map(|h| h.clone());
        match sftp_h {
            Some(ref h) => match self.sftp.read(h, offset, length) {
                Ok(data) if data.is_empty() => {
                    self.error_response(hdr, STATUS_END_OF_FILE, out);
                }
                Ok(data) => {
                    let data_offset = SMB2_HEADER_SIZE as u16 + 16;
                    let mut resp = Vec::with_capacity(16 + data.len());
                    resp.extend_from_slice(&17u16.to_le_bytes()); // StructureSize
                    resp.extend_from_slice(&data_offset.to_le_bytes()); // DataOffset (from header start)
                    resp.extend_from_slice(&(data.len() as u32).to_le_bytes()); // DataLength
                    resp.extend_from_slice(&0u32.to_le_bytes()); // DataRemaining
                    resp.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
                                                                 // Padding to align data
                    resp.push(0);
                    resp.extend_from_slice(&data);
                    hdr.write_response(STATUS_SUCCESS, &resp, out);
                }
                Err(_) => self.error_response(hdr, STATUS_ACCESS_DENIED, out),
            },
            None => self.error_response(hdr, STATUS_INVALID_PARAMETER, out),
        }
    }

    // ── WRITE ───────────────────────────────────────────────────────

    fn handle_write(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        if body.len() < 32 {
            self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
            return;
        }
        let data_offset = read_u16_le(body, 2) as usize;
        let length = read_u32_le(body, 4) as usize;
        let offset = read_u64_le(body, 8);
        let fid = self.resolve_fid(read_u64_le(body, 16));

        let data_start = data_offset.saturating_sub(SMB2_HEADER_SIZE);
        if data_start + length > body.len() {
            self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
            return;
        }
        let data = &body[data_start..data_start + length];

        let handle = match self.handles.get_mut(&fid) {
            Some(h) => h,
            None => {
                self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                return;
            }
        };

        // Lazy-open for write
        if handle.sftp_handle.is_none() {
            match self.sftp.open(&handle.path, 0x02, 0) {
                // WRITE
                Ok(h) => handle.sftp_handle = Some(h),
                Err(_) => {
                    self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                    return;
                }
            }
        }

        let sftp_h = handle.sftp_handle.as_ref().map(|h| h.clone());
        match sftp_h {
            Some(ref h) => match self.sftp.write(h, offset, data) {
                Ok(()) => {
                    self.cache.invalidate(&handle.path);
                    let mut resp = Vec::with_capacity(16);
                    resp.extend_from_slice(&17u16.to_le_bytes()); // StructureSize
                    resp.extend_from_slice(&0u16.to_le_bytes()); // Reserved
                    resp.extend_from_slice(&(length as u32).to_le_bytes()); // Count
                    resp.extend_from_slice(&0u32.to_le_bytes()); // Remaining
                    resp.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoOffset
                    resp.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoLength
                                                                 // Padding
                    resp.push(0);
                    hdr.write_response(STATUS_SUCCESS, &resp, out);
                }
                Err(_) => self.error_response(hdr, STATUS_ACCESS_DENIED, out),
            },
            None => self.error_response(hdr, STATUS_INVALID_PARAMETER, out),
        }
    }

    // ── QUERY_DIRECTORY ─────────────────────────────────────────────

    fn handle_query_directory(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        if body.len() < 24 {
            self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
            return;
        }
        let info_level = body[2];
        let flags = body[3];
        let fid = self.resolve_fid(read_u64_le(body, 8));
        let restart = flags & 0x01 != 0; // RESTART_SCANS

        let handle = match self.handles.get_mut(&fid) {
            Some(h) if h.is_dir => h,
            _ => {
                self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                return;
            }
        };

        // Fetch directory listing if not cached
        if handle.dir_entries.is_none() || restart {
            match self.sftp.readdir(&handle.path) {
                Ok(entries) => {
                    // Cache attrs for all entries
                    self.cache.insert_dir_entries(&handle.path, &entries);
                    handle.dir_entries = Some(entries);
                    handle.dir_offset = 0;
                }
                Err(_) => {
                    self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                    return;
                }
            }
        }

        let entries = match &handle.dir_entries {
            Some(e) => e,
            None => {
                self.error_response(hdr, STATUS_NO_MORE_FILES, out);
                return;
            }
        };

        if handle.dir_offset >= entries.len() {
            self.error_response(hdr, STATUS_NO_MORE_FILES, out);
            return;
        }

        // Build directory info response
        let mut dir_data = Vec::with_capacity(4096);
        let max_entries = 64; // batch size
        let mut count = 0;

        while handle.dir_offset < entries.len() && count < max_entries {
            let entry = &entries[handle.dir_offset];
            handle.dir_offset += 1;
            count += 1;

            let name_bytes = to_utf16le(&entry.name);
            let is_dir = entry.attrs.perm & 0o40000 != 0;
            let ft = unix_to_filetime(entry.attrs.mtime as u64);
            let file_attrs = if is_dir {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_ARCHIVE
            };

            let entry_start = dir_data.len();

            // FileBothDirectoryInformation layout (most compatible)
            dir_data.extend_from_slice(&0u32.to_le_bytes()); // NextEntryOffset (patched later)
            dir_data.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
            dir_data.extend_from_slice(&ft.to_le_bytes()); // CreationTime
            dir_data.extend_from_slice(&ft.to_le_bytes()); // LastAccessTime
            dir_data.extend_from_slice(&ft.to_le_bytes()); // LastWriteTime
            dir_data.extend_from_slice(&ft.to_le_bytes()); // ChangeTime
            dir_data.extend_from_slice(&entry.attrs.size.to_le_bytes()); // EndOfFile
            dir_data.extend_from_slice(&entry.attrs.size.to_le_bytes()); // AllocationSize
            dir_data.extend_from_slice(&file_attrs.to_le_bytes()); // FileAttributes
            dir_data.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes()); // FileNameLength
            dir_data.extend_from_slice(&0u32.to_le_bytes()); // EaSize

            if info_level == FILE_BOTH_DIRECTORY_INFORMATION
                || info_level == FILE_ID_BOTH_DIRECTORY_INFORMATION
            {
                dir_data.push(0); // ShortNameLength
                dir_data.push(0); // Reserved
                dir_data.extend_from_slice(&[0u8; 24]); // ShortName (unused)
            }

            if info_level == FILE_ID_BOTH_DIRECTORY_INFORMATION
                || info_level == FILE_ID_FULL_DIRECTORY_INFORMATION
            {
                dir_data.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
                dir_data.extend_from_slice(&(handle.dir_offset as u64).to_le_bytes());
                // FileId
            }

            dir_data.extend_from_slice(&name_bytes);

            // Align to 8 bytes
            while dir_data.len() % 8 != 0 {
                dir_data.push(0);
            }

            // Patch NextEntryOffset for previous entry
            if count > 1 {
                let _entry_len = dir_data.len() - entry_start;
                // Find previous entry's NextEntryOffset and patch it
                // (we need to track the previous start)
            }
            // Simpler: patch NextEntryOffset at entry_start
            let _current_len = dir_data.len();
            if handle.dir_offset < entries.len() && count < max_entries {
                // More entries coming — set offset to point to next
                // We'll patch this after the loop
            }
        }

        // Patch NextEntryOffset for all entries except last
        // Re-scan the buffer to fix offsets
        let mut pos = 0;
        loop {
            if pos + 4 > dir_data.len() {
                break;
            }
            // Find next entry by scanning for the pattern
            let name_len_off = pos + 60; // approximate offset to FileNameLength
            if name_len_off + 4 > dir_data.len() {
                break;
            }
            let name_len = read_u32_le(&dir_data, name_len_off) as usize;
            // Calculate this entry's total size (varies by info level)
            let base_size = match info_level {
                FILE_BOTH_DIRECTORY_INFORMATION => 94,
                FILE_ID_BOTH_DIRECTORY_INFORMATION => 104,
                _ => 68, // FILE_FULL_DIRECTORY_INFORMATION
            };
            let entry_size = base_size + name_len;
            let aligned = (entry_size + 7) & !7;

            if pos + aligned >= dir_data.len() {
                // Last entry — NextEntryOffset = 0 (already set)
                break;
            }
            // Patch NextEntryOffset
            let next_offset = aligned as u32;
            dir_data[pos..pos + 4].copy_from_slice(&next_offset.to_le_bytes());
            pos += aligned;
        }

        if dir_data.is_empty() {
            self.error_response(hdr, STATUS_NO_MORE_FILES, out);
            return;
        }

        let data_offset = SMB2_HEADER_SIZE as u16 + 8;
        let mut resp = Vec::with_capacity(8 + dir_data.len());
        resp.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
        resp.extend_from_slice(&data_offset.to_le_bytes()); // OutputBufferOffset
        resp.extend_from_slice(&(dir_data.len() as u32).to_le_bytes()); // OutputBufferLength
        resp.push(0); // Padding
        resp.extend_from_slice(&dir_data);

        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── QUERY_INFO ──────────────────────────────────────────────────

    fn handle_query_info(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        if body.len() < 32 {
            self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
            return;
        }
        let info_type = body[2];
        let file_info_class = body[3];
        let fid = self.resolve_fid(read_u64_le(body, 24));
        log::info!("QUERY_INFO: type={info_type} class={file_info_class} fid={fid}");

        let handle = match self.handles.get(&fid) {
            Some(h) => h,
            None => {
                self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                return;
            }
        };

        let path = handle.path.clone();
        let is_dir = handle.is_dir;

        let (attr, _) = match self.stat_cached(&path) {
            Ok(v) => v,
            Err(s) => {
                self.error_response(hdr, s, out);
                return;
            }
        };

        let ft = unix_to_filetime(attr.mtime as u64);
        let ft_access = unix_to_filetime(attr.atime as u64);
        let file_attrs = if is_dir {
            FILE_ATTRIBUTE_DIRECTORY
        } else {
            FILE_ATTRIBUTE_ARCHIVE
        };

        let mut info_data = Vec::with_capacity(128);

        match (info_type, file_info_class) {
            (SMB2_0_INFO_FILE, FILE_BASIC_INFORMATION) => {
                info_data.extend_from_slice(&ft.to_le_bytes()); // CreationTime
                info_data.extend_from_slice(&ft_access.to_le_bytes()); // LastAccessTime
                info_data.extend_from_slice(&ft.to_le_bytes()); // LastWriteTime
                info_data.extend_from_slice(&ft.to_le_bytes()); // ChangeTime
                info_data.extend_from_slice(&file_attrs.to_le_bytes()); // FileAttributes
                info_data.extend_from_slice(&0u32.to_le_bytes()); // Reserved
            }
            (SMB2_0_INFO_FILE, FILE_STANDARD_INFORMATION) => {
                info_data.extend_from_slice(&attr.size.to_le_bytes()); // AllocationSize
                info_data.extend_from_slice(&attr.size.to_le_bytes()); // EndOfFile
                info_data.extend_from_slice(&1u32.to_le_bytes()); // NumberOfLinks
                info_data.push(0); // DeletePending
                info_data.push(if is_dir { 1 } else { 0 }); // Directory
                info_data.extend_from_slice(&0u16.to_le_bytes()); // Reserved
            }
            (SMB2_0_INFO_FILE, FILE_INTERNAL_INFORMATION) => {
                info_data.extend_from_slice(&0u64.to_le_bytes()); // IndexNumber
            }
            (SMB2_0_INFO_FILE, FILE_EA_INFORMATION) => {
                info_data.extend_from_slice(&0u32.to_le_bytes()); // EaSize
            }
            (SMB2_0_INFO_FILE, FILE_NETWORK_OPEN_INFORMATION) => {
                info_data.extend_from_slice(&ft.to_le_bytes()); // CreationTime
                info_data.extend_from_slice(&ft_access.to_le_bytes()); // LastAccessTime
                info_data.extend_from_slice(&ft.to_le_bytes()); // LastWriteTime
                info_data.extend_from_slice(&ft.to_le_bytes()); // ChangeTime
                info_data.extend_from_slice(&attr.size.to_le_bytes()); // AllocationSize
                info_data.extend_from_slice(&attr.size.to_le_bytes()); // EndOfFile
                info_data.extend_from_slice(&file_attrs.to_le_bytes()); // FileAttributes
                info_data.extend_from_slice(&0u32.to_le_bytes()); // Reserved
            }
            (SMB2_0_INFO_FILE, FILE_ATTRIBUTE_TAG_INFORMATION) => {
                info_data.extend_from_slice(&file_attrs.to_le_bytes()); // FileAttributes
                info_data.extend_from_slice(&0u32.to_le_bytes()); // ReparseTag
            }
            (SMB2_0_INFO_FILE, FILE_STREAM_INFORMATION) => {
                // No alternate data streams
                self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                return;
            }
            (SMB2_0_INFO_FILE, FILE_ALL_INFORMATION) => {
                // BasicInformation
                info_data.extend_from_slice(&ft.to_le_bytes());
                info_data.extend_from_slice(&ft_access.to_le_bytes());
                info_data.extend_from_slice(&ft.to_le_bytes());
                info_data.extend_from_slice(&ft.to_le_bytes());
                info_data.extend_from_slice(&file_attrs.to_le_bytes());
                info_data.extend_from_slice(&0u32.to_le_bytes()); // Reserved
                                                                  // StandardInformation
                info_data.extend_from_slice(&attr.size.to_le_bytes());
                info_data.extend_from_slice(&attr.size.to_le_bytes());
                info_data.extend_from_slice(&1u32.to_le_bytes());
                info_data.push(0);
                info_data.push(if is_dir { 1 } else { 0 });
                info_data.extend_from_slice(&0u16.to_le_bytes());
                // InternalInformation
                info_data.extend_from_slice(&0u64.to_le_bytes());
                // EaInformation
                info_data.extend_from_slice(&0u32.to_le_bytes());
                // AccessInformation
                info_data.extend_from_slice(&MAXIMUM_ALLOWED.to_le_bytes());
                // PositionInformation
                info_data.extend_from_slice(&0u64.to_le_bytes());
                // ModeInformation
                info_data.extend_from_slice(&0u32.to_le_bytes());
                // AlignmentInformation
                info_data.extend_from_slice(&0u32.to_le_bytes());
                // NameInformation
                let name_bytes = to_utf16le(path.rsplit('/').next().unwrap_or(""));
                info_data.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
                info_data.extend_from_slice(&name_bytes);
            }
            (SMB2_0_INFO_FILE, FILE_POSITION_INFORMATION) => {
                info_data.extend_from_slice(&0u64.to_le_bytes());
            }
            (SMB2_0_INFO_FILESYSTEM, FS_SIZE_INFORMATION | FS_FULL_SIZE_INFORMATION) => {
                info_data.extend_from_slice(&(1024u64 * 1024 * 1024).to_le_bytes()); // TotalAllocationUnits
                info_data.extend_from_slice(&(512u64 * 1024 * 1024).to_le_bytes()); // AvailableAllocationUnits
                if file_info_class == FS_FULL_SIZE_INFORMATION {
                    info_data.extend_from_slice(&(512u64 * 1024 * 1024).to_le_bytes());
                    // CallerAvailableAllocationUnits
                }
                info_data.extend_from_slice(&1u32.to_le_bytes()); // SectorsPerAllocationUnit
                info_data.extend_from_slice(&4096u32.to_le_bytes()); // BytesPerSector
            }
            (SMB2_0_INFO_FILESYSTEM, FS_ATTRIBUTE_INFORMATION) => {
                info_data.extend_from_slice(&0x0000_0003u32.to_le_bytes()); // Attributes: case sensitive + case preserving
                info_data.extend_from_slice(&255u32.to_le_bytes()); // MaxNameLength
                let label = to_utf16le("SSHFS");
                info_data.extend_from_slice(&(label.len() as u32).to_le_bytes());
                info_data.extend_from_slice(&label);
            }
            (SMB2_0_INFO_FILESYSTEM, FS_VOLUME_INFORMATION) => {
                info_data.extend_from_slice(&ft.to_le_bytes()); // VolumeCreationTime
                info_data.extend_from_slice(&0u32.to_le_bytes()); // VolumeSerialNumber
                let label = to_utf16le("sshfs");
                info_data.extend_from_slice(&(label.len() as u32).to_le_bytes());
                info_data.push(0); // SupportsObjects
                info_data.push(0); // Reserved
                info_data.extend_from_slice(&label);
            }
            (SMB2_0_INFO_FILESYSTEM, FS_SECTOR_SIZE_INFORMATION) => {
                info_data.extend_from_slice(&4096u32.to_le_bytes()); // LogicalBytesPerSector
                info_data.extend_from_slice(&4096u32.to_le_bytes()); // PhysicalBytesPerSector
                info_data.extend_from_slice(&4096u32.to_le_bytes()); // FileSystemEffectiveBytesPerSector
                info_data.extend_from_slice(&0u32.to_le_bytes()); // Flags
                info_data.extend_from_slice(&0u32.to_le_bytes()); // ByteOffsetForSectorAlignment
                info_data.extend_from_slice(&0u32.to_le_bytes()); // ByteOffsetForPartitionAlignment
            }
            (SMB2_0_INFO_SECURITY, _) => {
                // Empty security descriptor
                info_data.extend_from_slice(&[0u8; 20]); // Minimal SD
            }
            _ => {
                log::debug!("QUERY_INFO: unsupported type={info_type} class={file_info_class}");
                self.error_response(hdr, STATUS_NOT_SUPPORTED, out);
                return;
            }
        }

        let data_offset = SMB2_HEADER_SIZE as u16 + 8;
        let mut resp = Vec::with_capacity(8 + info_data.len());
        resp.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
        resp.extend_from_slice(&data_offset.to_le_bytes()); // OutputBufferOffset
        resp.extend_from_slice(&(info_data.len() as u32).to_le_bytes()); // OutputBufferLength
        resp.push(0); // Padding
        resp.extend_from_slice(&info_data);

        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── SET_INFO ────────────────────────────────────────────────────

    fn handle_set_info(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        if body.len() < 24 {
            self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
            return;
        }
        let info_type = body[2];
        let file_info_class = body[3];
        let buf_length = read_u32_le(body, 4) as usize;
        let buf_offset = read_u16_le(body, 8) as usize;
        let fid = self.resolve_fid(read_u64_le(body, 16));

        let handle = match self.handles.get(&fid) {
            Some(h) => h,
            None => {
                self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                return;
            }
        };
        let path = handle.path.clone();

        let data_start = buf_offset.saturating_sub(SMB2_HEADER_SIZE);
        let info_data = if data_start + buf_length <= body.len() {
            &body[data_start..data_start + buf_length]
        } else {
            &[]
        };

        match (info_type, file_info_class) {
            (SMB2_0_INFO_FILE, FILE_RENAME_INFORMATION) => {
                if info_data.len() < 24 {
                    self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                    return;
                }
                let name_len = read_u32_le(info_data, 16) as usize;
                if 20 + name_len > info_data.len() {
                    self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                    return;
                }
                let new_name = from_utf16le(&info_data[20..20 + name_len]);
                let new_path = self.full_path(&new_name);

                match self.sftp.rename(&path, &new_path) {
                    Ok(()) => {
                        self.cache.invalidate(&path);
                        self.cache.invalidate(&new_path);
                        // Update handle path
                        if let Some(h) = self.handles.get_mut(&fid) {
                            h.path = new_path;
                        }
                    }
                    Err(_) => {
                        self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                        return;
                    }
                }
            }
            (SMB2_0_INFO_FILE, FILE_DISPOSITION_INFORMATION) => {
                let delete = info_data.first().copied().unwrap_or(0) != 0;
                if delete {
                    let is_dir = handle.is_dir;
                    let result = if is_dir {
                        self.sftp.rmdir(&path)
                    } else {
                        self.sftp.remove(&path)
                    };
                    match result {
                        Ok(()) => self.cache.invalidate(&path),
                        Err(_) => {
                            self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                            return;
                        }
                    }
                }
            }
            (SMB2_0_INFO_FILE, FILE_BASIC_INFORMATION) => {
                // Set timestamps/attributes — best effort via SFTP setstat
                if info_data.len() >= 36 {
                    if let Ok((mut attr, _)) = self.stat_cached(&path) {
                        let new_atime = read_u64_le(info_data, 8);
                        let new_mtime = read_u64_le(info_data, 16);
                        if new_atime != 0 {
                            attr.atime = filetime_to_unix(new_atime) as u32;
                        }
                        if new_mtime != 0 {
                            attr.mtime = filetime_to_unix(new_mtime) as u32;
                        }
                        let _ = self.sftp.setstat(&path, &attr);
                        self.cache.invalidate(&path);
                    }
                }
            }
            _ => {
                log::debug!("SET_INFO: unsupported type={info_type} class={file_info_class}");
                // Return success anyway — macOS sends many SET_INFO we can ignore
            }
        }

        let mut resp = Vec::with_capacity(2);
        resp.extend_from_slice(&2u16.to_le_bytes()); // StructureSize
        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── FLUSH ───────────────────────────────────────────────────────

    fn handle_flush(&mut self, hdr: &Smb2Header, out: &mut Vec<u8>) {
        let mut resp = Vec::with_capacity(4);
        resp.extend_from_slice(&4u16.to_le_bytes());
        resp.extend_from_slice(&0u16.to_le_bytes());
        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── IOCTL ───────────────────────────────────────────────────────

    fn handle_ioctl(&mut self, hdr: &Smb2Header, out: &mut Vec<u8>) {
        self.error_response(hdr, STATUS_INVALID_DEVICE_REQUEST, out);
    }
}

// ── SPNEGO init token ───────────────────────────────────────────────
