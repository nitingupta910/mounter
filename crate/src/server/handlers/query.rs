//! SMB2 command handlers.

use super::super::pattern::{is_spotlight_inhibitor, smb_pattern_match};
use super::super::session::SmbSession;
use crate::sftp::{DirEntry, FileAttr};
use crate::smb2::*;
use std::time::{SystemTime, UNIX_EPOCH};

impl SmbSession {
    pub(crate) fn handle_query_directory(
        &mut self,
        hdr: &Smb2Header,
        body: &[u8],
        out: &mut Vec<u8>,
    ) {
        if body.len() < 24 {
            self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
            return;
        }
        let info_level = body[2];
        let flags = body[3];
        let fid = self.resolve_fid(read_u64_le(body, 8));
        let restart = flags & 0x01 != 0; // RESTART_SCANS

        // Parse search pattern (MS-SMB2 2.2.33)
        let name_offset = if body.len() >= 26 {
            read_u16_le(body, 24) as usize
        } else {
            0
        };
        let name_length = if body.len() >= 28 {
            read_u16_le(body, 26) as usize
        } else {
            0
        };
        let pattern = if name_length > 0 {
            let name_start = name_offset.saturating_sub(SMB2_HEADER_SIZE);
            if name_start + name_length <= body.len() {
                from_utf16le(&body[name_start..name_start + name_length])
            } else {
                "*".to_string()
            }
        } else {
            "*".to_string()
        };
        log::debug!(
            "QUERY_DIRECTORY: info_level={info_level} flags=0x{flags:02x} fid={fid} restart={restart} pattern=\"{pattern}\""
        );

        let handle = match self.handles.get_mut(&fid) {
            Some(h) if h.is_dir => h,
            _ => {
                self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                return;
            }
        };

        // Fetch directory listing — check session-level dir cache first,
        // then per-handle cache, then fall back to SFTP readdir.
        if handle.dir_entries.is_none() || restart {
            let dir_path = handle.path.clone();
            if let Some(cached) = self.dir_cache.get(&dir_path) {
                log::debug!("QUERY_DIRECTORY: dir cache hit for {dir_path}");
                handle.dir_entries = Some(cached);
                if restart {
                    handle.dir_offset = 0;
                }
            } else {
                match self.sftp.readdir(&dir_path) {
                    Ok(entries) => {
                        // Populate both caches
                        self.cache.insert_dir_entries(&dir_path, &entries);
                        self.dir_cache.insert(dir_path.clone(), entries);
                        handle.dir_entries = self.dir_cache.get(&dir_path);
                        handle.dir_offset = 0;
                    }
                    Err(_) => {
                        self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                        return;
                    }
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

        // Fake Spotlight-inhibitor files so macOS skips volume indexing
        let fake_entry;
        if is_spotlight_inhibitor(&pattern) {
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32;
            fake_entry = Some(DirEntry {
                name: pattern.clone(),
                attrs: FileAttr {
                    size: 0,
                    uid: 0,
                    gid: 0,
                    perm: 0o100444,
                    atime: now_secs,
                    mtime: now_secs,
                },
            });
        } else {
            fake_entry = None;
        }

        // Filter entries by search pattern
        let is_wildcard = pattern == "*";
        let filtered: Vec<&DirEntry> = if let Some(ref fe) = fake_entry {
            vec![fe]
        } else if is_wildcard {
            // Wildcard: return entries starting from dir_offset
            entries.iter().skip(handle.dir_offset).collect()
        } else {
            // Specific filename or pattern: match against entry names
            entries
                .iter()
                .filter(|e| smb_pattern_match(&pattern, &e.name))
                .collect()
        };

        if filtered.is_empty() {
            self.error_response(hdr, STATUS_NO_MORE_FILES, out);
            return;
        }

        // Build directory info response
        // Build directory entries. Track entry start positions for NextEntryOffset patching.
        let single_entry = flags & 0x02 != 0; // RETURN_SINGLE_ENTRY
        let mut dir_data = Vec::with_capacity(if single_entry {
            256
        } else {
            filtered.len() * 128
        });
        let max_entries = if single_entry { 1 } else { usize::MAX };
        let mut count = 0;
        let mut entry_starts: Vec<usize> = Vec::new();

        for entry in &filtered {
            if count >= max_entries {
                break;
            }
            if is_wildcard {
                handle.dir_offset += 1;
            }
            count += 1;

            let name_bytes = to_utf16le(&entry.name);
            let is_dir = entry.attrs.perm & 0o40000 != 0;
            let ft_create = unix_to_filetime(entry.attrs.mtime as u64);
            let ft_access = unix_to_filetime(entry.attrs.atime as u64);
            let ft_write = unix_to_filetime(entry.attrs.mtime as u64);
            let file_attrs = if is_dir {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_ARCHIVE
            };

            // Pad previous entry to 8-byte alignment before starting new one
            if !entry_starts.is_empty() {
                while dir_data.len() % 8 != 0 {
                    dir_data.push(0);
                }
            }

            let entry_start = dir_data.len();
            entry_starts.push(entry_start);

            // FILE_ID_BOTH_DIRECTORY_INFORMATION (level 37) — what macOS requests.
            // Layout per MS-FSCC 2.4.17:
            //   NextEntryOffset(4) + FileIndex(4) + times(4*8=32) +
            //   EndOfFile(8) + AllocationSize(8) + FileAttributes(4) +
            //   FileNameLength(4) + EaSize(4) + ShortNameLength(1) +
            //   Reserved1(1) + ShortName(24) + Reserved2(2) + FileId(8) +
            //   FileName(variable)
            // Fixed part = 104 bytes

            dir_data.extend_from_slice(&0u32.to_le_bytes()); // NextEntryOffset (patched)
            dir_data.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
            dir_data.extend_from_slice(&ft_create.to_le_bytes()); // CreationTime
            dir_data.extend_from_slice(&ft_access.to_le_bytes()); // LastAccessTime
            dir_data.extend_from_slice(&ft_write.to_le_bytes()); // LastWriteTime
            dir_data.extend_from_slice(&ft_write.to_le_bytes()); // ChangeTime
            dir_data.extend_from_slice(&entry.attrs.size.to_le_bytes()); // EndOfFile
            dir_data.extend_from_slice(&entry.attrs.size.to_le_bytes()); // AllocationSize
            dir_data.extend_from_slice(&file_attrs.to_le_bytes()); // FileAttributes
            dir_data.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes()); // FileNameLength
            dir_data.extend_from_slice(&0u32.to_le_bytes()); // EaSize
            dir_data.push(0); // ShortNameLength
            dir_data.push(0); // Reserved1
            dir_data.extend_from_slice(&[0u8; 24]); // ShortName (empty)
            dir_data.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
            dir_data.extend_from_slice(&(count as u64).to_le_bytes()); // FileId
            dir_data.extend_from_slice(&name_bytes); // FileName
        }

        // Patch NextEntryOffset: each entry points to the next, last = 0
        for i in 0..entry_starts.len().saturating_sub(1) {
            let this_start = entry_starts[i];
            let next_start = entry_starts[i + 1];
            let offset = (next_start - this_start) as u32;
            dir_data[this_start..this_start + 4].copy_from_slice(&offset.to_le_bytes());
        }

        if dir_data.is_empty() {
            self.error_response(hdr, STATUS_NO_MORE_FILES, out);
            return;
        }

        // OutputBuffer starts at body byte 8 = header offset 72
        let data_offset = (SMB2_HEADER_SIZE + 8) as u16;
        let mut resp = Vec::with_capacity(8 + dir_data.len());
        resp.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
        resp.extend_from_slice(&data_offset.to_le_bytes()); // OutputBufferOffset
        resp.extend_from_slice(&(dir_data.len() as u32).to_le_bytes()); // OutputBufferLength
        // No padding — OutputBuffer starts immediately at byte 8
        resp.extend_from_slice(&dir_data);

        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── QUERY_INFO ──────────────────────────────────────────────────

    pub(crate) fn handle_query_info(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        if body.len() < 32 {
            self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
            return;
        }
        let info_type = body[2];
        let file_info_class = body[3];
        let fid = self.resolve_fid(read_u64_le(body, 24));
        log::debug!("QUERY_INFO: type={info_type} class={file_info_class} fid={fid}");

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

        let data_offset = (SMB2_HEADER_SIZE + 8) as u16;
        let mut resp = Vec::with_capacity(8 + info_data.len());
        resp.extend_from_slice(&9u16.to_le_bytes()); // StructureSize
        resp.extend_from_slice(&data_offset.to_le_bytes()); // OutputBufferOffset
        resp.extend_from_slice(&(info_data.len() as u32).to_le_bytes()); // OutputBufferLength
        resp.extend_from_slice(&info_data);

        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── SET_INFO ────────────────────────────────────────────────────

    pub(crate) fn handle_set_info(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
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
                let new_path = match self.full_path(&new_name) {
                    Ok(path) => path,
                    Err(status) => {
                        self.error_response(hdr, status, out);
                        return;
                    }
                };

                match self.sftp.rename(&path, &new_path) {
                    Ok(()) => {
                        self.invalidate_path(&path);
                        self.invalidate_path(&new_path);
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
                        Ok(()) => self.invalidate_path(&path),
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
                        self.invalidate_path(&path);
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
}
