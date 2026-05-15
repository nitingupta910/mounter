//! SMB2 command handlers.

use super::super::session::SmbSession;
use crate::smb2::*;

impl SmbSession {
    pub(crate) fn handle_flush(&mut self, hdr: &Smb2Header, out: &mut Vec<u8>) {
        let mut resp = Vec::with_capacity(4);
        resp.extend_from_slice(&4u16.to_le_bytes());
        resp.extend_from_slice(&0u16.to_le_bytes());
        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── LOCK ────────────────────────────────────────────────────────

    pub(crate) fn handle_lock(&mut self, hdr: &Smb2Header, out: &mut Vec<u8>) {
        // MS-SMB2 2.2.26 LOCK Response: StructureSize=4, Reserved=0
        let mut resp = Vec::with_capacity(4);
        resp.extend_from_slice(&4u16.to_le_bytes());
        resp.extend_from_slice(&0u16.to_le_bytes());
        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── IOCTL ───────────────────────────────────────────────────────

    pub(crate) fn handle_ioctl(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        if body.len() < 56 {
            self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
            return;
        }
        let ctl_code = read_u32_le(body, 4);
        let fid = self.resolve_fid(read_u64_le(body, 8));
        log::debug!("IOCTL: ctl_code=0x{ctl_code:08x} fid={fid}");
        let input_offset = read_u32_le(body, 24) as usize;
        let input_count = read_u32_le(body, 28) as usize;

        const FSCTL_PIPE_TRANSACT: u32 = 0x0011C017;

        if ctl_code == FSCTL_PIPE_TRANSACT {
            let is_pipe = self.handles.get(&fid).map_or(false, |h| h.is_pipe);
            if !is_pipe {
                log::debug!("IOCTL PIPE_TRANSACT: fid={fid} not a pipe handle");
                self.error_response(hdr, STATUS_INVALID_PARAMETER, out);
                return;
            }

            // Extract DCE/RPC input data
            let in_start = input_offset.saturating_sub(SMB2_HEADER_SIZE);
            let rpc_in = if in_start + input_count <= body.len() {
                &body[in_start..in_start + input_count]
            } else {
                &[]
            };

            log::debug!(
                "IOCTL PIPE_TRANSACT: input_len={} pkt_type={}",
                rpc_in.len(),
                rpc_in.get(2).copied().unwrap_or(0xff)
            );
            let rpc_out = self.handle_dcerpc(rpc_in);
            log::debug!("IOCTL PIPE_TRANSACT: response_len={}", rpc_out.len());

            // Build IOCTL response
            let data_offset = (SMB2_HEADER_SIZE + 48) as u32;
            let mut resp = Vec::with_capacity(48 + rpc_out.len());
            resp.extend_from_slice(&49u16.to_le_bytes()); // StructureSize
            resp.extend_from_slice(&0u16.to_le_bytes()); // Reserved
            resp.extend_from_slice(&ctl_code.to_le_bytes());
            resp.extend_from_slice(&fid.to_le_bytes()); // FileId.Persistent
            resp.extend_from_slice(&fid.to_le_bytes()); // FileId.Volatile
            resp.extend_from_slice(&0u32.to_le_bytes()); // InputOffset
            resp.extend_from_slice(&0u32.to_le_bytes()); // InputCount
            resp.extend_from_slice(&data_offset.to_le_bytes()); // OutputOffset
            resp.extend_from_slice(&(rpc_out.len() as u32).to_le_bytes()); // OutputCount
            resp.extend_from_slice(&0u32.to_le_bytes()); // Flags
            resp.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
            resp.extend_from_slice(&rpc_out);
            hdr.write_response(STATUS_SUCCESS, &resp, out);
        } else {
            self.error_response(hdr, STATUS_INVALID_DEVICE_REQUEST, out);
        }
    }

    // ── DCE/RPC ─────────────────────────────────────────────────────
}
