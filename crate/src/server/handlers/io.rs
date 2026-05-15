//! SMB2 command handlers.

use super::super::session::SmbSession;
use super::super::types::ReadAhead;
use crate::sftp::{SSH_FXF_READ, SSH_FXF_WRITE, SftpError};
use crate::smb2::*;

impl SmbSession {
    pub(crate) fn handle_read(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        if body.len() < 32 {
            self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
            return;
        }
        let length = read_u32_le(body, 4) as u64;
        let offset = read_u64_le(body, 8);
        let fid = self.resolve_fid(read_u64_le(body, 16));

        let handle = match self.handles.get_mut(&fid) {
            Some(h) => h,
            None => {
                self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                return;
            }
        };

        // Named pipe read: return buffered DCE/RPC response
        if handle.is_pipe {
            if let Some(data) = handle.pipe_response.take() {
                Self::write_read_response(hdr, &data, out);
            } else {
                self.error_response(hdr, STATUS_END_OF_FILE, out);
            }
            return;
        }

        // Lazy-open SFTP handle
        if handle.sftp_handle.is_none() {
            match self.sftp.open(&handle.path, SSH_FXF_READ, 0) {
                Ok(h) => handle.sftp_handle = Some(h),
                Err(_) => {
                    self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                    return;
                }
            }
        }

        // Try to serve from read-ahead buffer first
        if let Some(ref ra) = handle.readahead {
            if offset >= ra.offset && offset + length <= ra.offset + ra.data.len() as u64 {
                let start = (offset - ra.offset) as usize;
                let end = start + length as usize;
                let data = &ra.data[start..end];
                Self::write_read_response(hdr, data, out);
                return;
            }
        }

        // Read from SFTP — cache result for small follow-up reads.
        // On disconnect, the ReconnectingSftp will reconnect, but our handle
        // is dead. Reopen and retry once.
        let sftp_h = handle.sftp_handle.as_ref().map(|h| h.clone());
        let path = handle.path.clone();
        match sftp_h {
            Some(ref h) => match self.sftp.read(h, offset, length as u32) {
                Ok(data) if data.is_empty() => {
                    self.error_response(hdr, STATUS_END_OF_FILE, out);
                }
                Ok(data) => {
                    let respond_len = (length as usize).min(data.len());
                    Self::write_read_response(hdr, &data[..respond_len], out);
                    if let Some(h) = self.handles.get_mut(&fid) {
                        h.readahead = Some(ReadAhead { data, offset });
                    }
                }
                Err(SftpError::Disconnected) | Err(SftpError::Protocol(_)) => {
                    // Handle is dead or stream corrupt — reconnect, reopen, retry
                    self.on_reconnect();
                    match self.sftp.open(&path, SSH_FXF_READ, 0) {
                        Ok(new_h) => match self.sftp.read(&new_h, offset, length as u32) {
                            Ok(data) if data.is_empty() => {
                                self.error_response(hdr, STATUS_END_OF_FILE, out);
                            }
                            Ok(data) => {
                                let respond_len = (length as usize).min(data.len());
                                Self::write_read_response(hdr, &data[..respond_len], out);
                                if let Some(h) = self.handles.get_mut(&fid) {
                                    h.sftp_handle = Some(new_h);
                                    h.readahead = Some(ReadAhead { data, offset });
                                }
                            }
                            Err(_) => self.error_response(hdr, STATUS_ACCESS_DENIED, out),
                        },
                        Err(_) => self.error_response(hdr, STATUS_ACCESS_DENIED, out),
                    }
                }
                Err(_) => self.error_response(hdr, STATUS_ACCESS_DENIED, out),
            },
            None => self.error_response(hdr, STATUS_INVALID_PARAMETER, out),
        }
    }

    pub(crate) fn write_read_response(hdr: &Smb2Header, data: &[u8], out: &mut Vec<u8>) {
        let data_offset = SMB2_HEADER_SIZE as u16 + 16;
        let mut resp = Vec::with_capacity(16 + data.len());
        resp.extend_from_slice(&17u16.to_le_bytes()); // StructureSize
        resp.extend_from_slice(&data_offset.to_le_bytes()); // DataOffset
        resp.extend_from_slice(&(data.len() as u32).to_le_bytes()); // DataLength
        resp.extend_from_slice(&0u32.to_le_bytes()); // DataRemaining
        resp.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
        resp.extend_from_slice(data);
        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── WRITE ───────────────────────────────────────────────────────

    pub(crate) fn handle_write(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
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

        let is_pipe = self.handles.get(&fid).map_or(false, |h| h.is_pipe);

        if is_pipe {
            // Named pipe write: process DCE/RPC and buffer response for READ
            let rpc_out = self.handle_dcerpc(data);
            if let Some(h) = self.handles.get_mut(&fid) {
                h.pipe_response = Some(rpc_out);
            }
            // WRITE response
            let mut resp = Vec::with_capacity(16);
            resp.extend_from_slice(&17u16.to_le_bytes()); // StructureSize
            resp.extend_from_slice(&0u16.to_le_bytes()); // Reserved
            resp.extend_from_slice(&(length as u32).to_le_bytes()); // Count
            resp.extend_from_slice(&0u32.to_le_bytes()); // Remaining
            resp.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoOffset
            resp.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoLength
            hdr.write_response(STATUS_SUCCESS, &resp, out);
            return;
        }

        let handle = match self.handles.get_mut(&fid) {
            Some(h) => h,
            None => {
                self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                return;
            }
        };

        // Lazy-open for write
        if handle.sftp_handle.is_none() {
            match self.sftp.open(&handle.path, SSH_FXF_WRITE, 0) {
                // WRITE
                Ok(h) => handle.sftp_handle = Some(h),
                Err(_) => {
                    self.error_response(hdr, STATUS_ACCESS_DENIED, out);
                    return;
                }
            }
        }

        let sftp_h = handle.sftp_handle.as_ref().map(|h| h.clone());
        let write_path = handle.path.clone();
        handle.readahead = None; // invalidate — data is changing
        let write_result = match sftp_h {
            Some(ref h) => match self.sftp.write(h, offset, data) {
                Err(SftpError::Disconnected) | Err(SftpError::Protocol(_)) => {
                    // Reconnect happened or stream corrupt, reopen handle and retry
                    self.on_reconnect();
                    match self.sftp.open(&write_path, SSH_FXF_WRITE, 0) {
                        Ok(new_h) => {
                            let r = self.sftp.write(&new_h, offset, data);
                            if let Some(h) = self.handles.get_mut(&fid) {
                                h.sftp_handle = Some(new_h);
                            }
                            r
                        }
                        Err(e) => Err(e),
                    }
                }
                other => other,
            },
            None => Err(SftpError::Disconnected),
        };
        match write_result {
            Ok(()) => {
                self.invalidate_path(&write_path);
                let mut resp = Vec::with_capacity(16);
                resp.extend_from_slice(&17u16.to_le_bytes()); // StructureSize
                resp.extend_from_slice(&0u16.to_le_bytes()); // Reserved
                resp.extend_from_slice(&(length as u32).to_le_bytes()); // Count
                resp.extend_from_slice(&0u32.to_le_bytes()); // Remaining
                resp.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoOffset
                resp.extend_from_slice(&0u16.to_le_bytes()); // WriteChannelInfoLength
                resp.push(0); // Padding
                hdr.write_response(STATUS_SUCCESS, &resp, out);
            }
            Err(_) => self.error_response(hdr, STATUS_ACCESS_DENIED, out),
        }
    }

    // ── QUERY_DIRECTORY ─────────────────────────────────────────────
}
