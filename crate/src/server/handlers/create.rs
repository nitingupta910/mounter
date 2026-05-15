//! SMB2 command handlers.

use super::super::pattern::is_spotlight_inhibitor;
use super::super::session::SmbSession;
use super::super::types::OpenHandle;
use crate::sftp::{FileAttr, SSH_FXF_CREAT, SSH_FXF_READ, SSH_FXF_TRUNC, SSH_FXF_WRITE};
use crate::smb2::*;
use std::time::{SystemTime, UNIX_EPOCH};

impl SmbSession {
    pub(crate) fn handle_create(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
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

        // IPC$ pipe: handle named pipes for share enumeration
        if self.ipc_tree_id == Some(hdr.tree_id) {
            let pipe_name = rel_name.to_ascii_lowercase();
            if pipe_name == "srvsvc" {
                log::debug!("CREATE: opening pipe srvsvc");
                let handle_id = self.alloc_handle();
                self.last_create_handle = handle_id;
                self.handles.insert(
                    handle_id,
                    OpenHandle {
                        sftp_handle: None,
                        path: "srvsvc".into(),
                        is_dir: false,
                        is_pipe: true,
                        pipe_response: None,
                        dir_entries: None,
                        dir_offset: 0,
                        readahead: None,
                    },
                );
                // Minimal CREATE response for a pipe
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let ft = unix_to_filetime(now);
                let mut resp = Vec::with_capacity(96);
                resp.extend_from_slice(&89u16.to_le_bytes());
                resp.push(0);
                resp.push(0);
                resp.extend_from_slice(&1u32.to_le_bytes()); // FILE_OPENED
                for _ in 0..4 {
                    resp.extend_from_slice(&ft.to_le_bytes());
                }
                resp.extend_from_slice(&0u64.to_le_bytes()); // AllocationSize
                resp.extend_from_slice(&0u64.to_le_bytes()); // EndOfFile
                resp.extend_from_slice(&0x00000080u32.to_le_bytes()); // FILE_ATTRIBUTE_NORMAL
                resp.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
                resp.extend_from_slice(&handle_id.to_le_bytes());
                resp.extend_from_slice(&handle_id.to_le_bytes());
                resp.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsOffset
                resp.extend_from_slice(&0u32.to_le_bytes()); // CreateContextsLength
                hdr.write_response(STATUS_SUCCESS, &resp, out);
            } else {
                self.error_response(hdr, STATUS_OBJECT_NAME_NOT_FOUND, out);
            }
            return;
        }

        let path = match self.full_path(&rel_name) {
            Ok(path) => path,
            Err(status) => {
                self.error_response(hdr, status, out);
                return;
            }
        };
        let want_dir = create_options & FILE_DIRECTORY_FILE != 0;

        log::debug!("CREATE: path={path} disposition={create_disposition} dir={want_dir}");

        // Fake Spotlight-inhibitor files so macOS doesn't recursively index the volume
        let basename = rel_name.rsplit(['/', '\\']).next().unwrap_or("");
        if is_spotlight_inhibitor(basename) && !rel_name.contains('/') && !rel_name.contains('\\') {
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32;
            let fake_attr = FileAttr {
                size: 0,
                uid: 0,
                gid: 0,
                perm: 0o100444,
                atime: now_secs,
                mtime: now_secs,
            };
            self.respond_create_success(hdr, &path, &fake_attr, false, out);
            return;
        }

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
                            self.invalidate_path(&path);
                            match self.stat_cached(&path) {
                                Ok((attr, is_dir)) => {
                                    self.respond_create_success(hdr, &path, &attr, is_dir, out);
                                }
                                Err(s) => self.error_response(hdr, s, out),
                            }
                        } else {
                            match self.sftp.open(
                                &path,
                                SSH_FXF_CREAT | SSH_FXF_READ | SSH_FXF_WRITE,
                                0o644,
                            ) {
                                Ok(sftp_handle) => {
                                    let _ = self.sftp.close(&sftp_handle);
                                    self.invalidate_path(&path);
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
                    match self.sftp.open(
                        &path,
                        SSH_FXF_CREAT | SSH_FXF_WRITE | SSH_FXF_TRUNC,
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
                }
                self.invalidate_path(&path);
                match self.stat_cached(&path) {
                    Ok((attr, is_dir)) => {
                        self.respond_create_success(hdr, &path, &attr, is_dir, out);
                    }
                    Err(s) => self.error_response(hdr, s, out),
                }
            }
            FILE_OVERWRITE | FILE_OVERWRITE_IF => {
                match self
                    .sftp
                    .open(&path, SSH_FXF_CREAT | SSH_FXF_TRUNC | SSH_FXF_WRITE, 0o644)
                {
                    Ok(h) => {
                        let _ = self.sftp.close(&h);
                    }
                    Err(_) => {
                        self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                        return;
                    }
                }
                self.invalidate_path(&path);
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

    pub(crate) fn respond_create_success(
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
                is_pipe: false,
                pipe_response: None,
                dir_entries: None,
                dir_offset: 0,
                readahead: None,
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

        log::debug!(
            "CREATE OK: path={path} is_dir={is_dir} file_attrs=0x{file_attrs:08x} size={} handle={handle_id}",
            attr.size
        );
        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── CLOSE ───────────────────────────────────────────────────────

    pub(crate) fn handle_close(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
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
}
