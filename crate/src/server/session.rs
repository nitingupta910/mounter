//! SMB2 session state and command dispatch.

use super::cache::{AttrCache, DirCache};
use super::pattern::is_apple_metadata;
use super::types::OpenHandle;
use crate::sftp::{FileAttr, ReconnectingSftp, SftpError};
use crate::smb2::*;
use std::collections::HashMap;
use std::sync::Arc;

// ── SMB2 Server Session ─────────────────────────────────────────────

pub struct SmbSession {
    pub(crate) sftp: Arc<ReconnectingSftp>,
    pub(crate) root_path: String,
    pub(crate) share_name: String,
    pub(crate) smb_user: String,
    pub(crate) session_id: u64,
    pub(crate) tree_id: u32,
    pub(crate) next_tree_id: u32,
    pub(crate) ipc_tree_id: Option<u32>,
    pub(crate) handles: HashMap<u64, OpenHandle>,
    pub(crate) next_handle: u64,
    pub(crate) cache: AttrCache,
    pub(crate) dir_cache: DirCache,
    pub(crate) auth_phase: u8,
    /// Last handle created — used for related compound requests where
    /// QUERY_INFO/CLOSE reference FileId=0xFFFFFFFF meaning "use CREATE's handle."
    pub(crate) last_create_handle: u64,
    pub(crate) msg_count: u64,
}

impl SmbSession {
    pub fn new(
        sftp: Arc<ReconnectingSftp>,
        root_path: String,
        share_name: String,
        smb_user: String,
    ) -> Self {
        SmbSession {
            sftp,
            root_path,
            share_name,
            smb_user,
            session_id: 0x0000_0001_0000_0001,
            tree_id: 1,
            next_tree_id: 2,
            ipc_tree_id: None,
            handles: HashMap::new(),
            next_handle: 1,
            cache: AttrCache::new(),
            dir_cache: DirCache::new(),
            auth_phase: 0,
            last_create_handle: 0,
            msg_count: 0,
        }
    }

    /// Resolve FileId — handles 0xFFFFFFFFFFFFFFFF sentinel for related compounds.
    pub(crate) fn resolve_fid(&self, fid: u64) -> u64 {
        if fid == 0xFFFF_FFFF_FFFF_FFFF {
            self.last_create_handle
        } else {
            fid
        }
    }

    /// Invalidate all caches for a path (attr + parent dir listing).
    pub(crate) fn invalidate_path(&mut self, path: &str) {
        self.cache.invalidate(path);
        if let Some((parent, _)) = path.rsplit_once('/') {
            self.dir_cache.invalidate(parent);
        }
    }

    /// Called after SFTP reconnect — all SFTP file handles are dead,
    /// and remote state may have changed.
    pub(crate) fn on_reconnect(&mut self) {
        log::info!("Flushing caches and handles after reconnect");
        // Invalidate all SFTP handles — they belong to the dead session
        for (_id, handle) in self.handles.iter_mut() {
            handle.sftp_handle = None;
            handle.readahead = None;
        }
        // Flush all caches — remote state may have changed
        self.cache = AttrCache::new();
        self.dir_cache = DirCache::new();
    }

    pub(crate) fn full_path(&self, rel: &str) -> Result<String, u32> {
        if rel.is_empty() || rel == "\\" || rel == "/" {
            Ok(self.root_path.clone())
        } else {
            let normalized = rel.replace('\\', "/");
            if normalized.starts_with('/')
                || normalized.chars().any(|c| c == '\0' || c.is_control())
            {
                return Err(STATUS_OBJECT_PATH_NOT_FOUND);
            }

            let mut safe_parts = Vec::new();
            for part in normalized.split('/') {
                if part.is_empty() || part == "." || part == ".." {
                    return Err(STATUS_OBJECT_PATH_NOT_FOUND);
                }
                safe_parts.push(part);
            }

            Ok(format!("{}/{}", self.root_path, safe_parts.join("/")))
        }
    }

    pub(crate) fn alloc_handle(&mut self) -> u64 {
        let h = self.next_handle;
        self.next_handle += 1;
        h
    }

    pub(crate) fn stat_cached(&mut self, path: &str) -> Result<(FileAttr, bool), u32> {
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
        // Periodic cache eviction every 256 messages
        self.msg_count += 1;
        if self.msg_count % 256 == 0 {
            self.cache.evict_expired();
            self.dir_cache.evict_expired();
        }

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
            SMB2_LOCK => self.handle_lock(&hdr, &mut response),
            SMB2_QUERY_DIRECTORY => self.handle_query_directory(&hdr, body, &mut response),
            SMB2_QUERY_INFO => self.handle_query_info(&hdr, body, &mut response),
            SMB2_SET_INFO => self.handle_set_info(&hdr, body, &mut response),
            SMB2_FLUSH => self.handle_flush(&hdr, &mut response),
            SMB2_IOCTL => self.handle_ioctl(&hdr, body, &mut response),
            _ => {
                log::warn!("Unsupported SMB2 command: 0x{:04x}", hdr.command);
                self.error_response(&hdr, STATUS_NOT_SUPPORTED, &mut response);
            }
        }
        response
    }

    pub(crate) fn error_response(&self, hdr: &Smb2Header, status: u32, out: &mut Vec<u8>) {
        // 9-byte error response body
        let mut body = Vec::with_capacity(9);
        body.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
        body.push(0); // ErrorContextCount
        body.push(0); // Reserved
        body.extend_from_slice(&0u32.to_le_bytes()); // ByteCount
        body.push(0); // ErrorData (1 byte padding)
        hdr.write_response(status, &body, out);
    }
}
