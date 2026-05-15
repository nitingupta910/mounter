//! SMB2 command handlers.

use super::super::session::SmbSession;
use crate::smb2::*;

impl SmbSession {
    pub(crate) fn handle_dcerpc(&self, input: &[u8]) -> Vec<u8> {
        if input.len() < 16 {
            return Vec::new();
        }
        let pkt_type = input[2];
        let call_id = read_u32_le(input, 12);

        match pkt_type {
            11 => self.dcerpc_bind_ack(call_id, input),
            0 => self.dcerpc_request(call_id, input),
            _ => Vec::new(),
        }
    }

    pub(crate) fn dcerpc_bind_ack(&self, call_id: u32, _input: &[u8]) -> Vec<u8> {
        // NDR transfer syntax UUID: 8a885d04-1ceb-11c9-9fe8-08002b104860
        let ndr_syntax: [u8; 16] = [
            0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
            0x48, 0x60,
        ];

        let secondary_addr = b"\\PIPE\\srvsvc\0";
        let addr_len = secondary_addr.len() as u16;

        let mut pdu = Vec::with_capacity(100);
        // DCE/RPC common header (16 bytes)
        pdu.push(5); // version
        pdu.push(0); // minor
        pdu.push(12); // bind_ack
        pdu.push(0x03); // first+last frag
        pdu.extend_from_slice(&0x00000010u32.to_le_bytes()); // data rep (LE)
        pdu.extend_from_slice(&0u16.to_le_bytes()); // frag_length (patched later)
        pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length
        pdu.extend_from_slice(&call_id.to_le_bytes());
        // bind_ack body
        pdu.extend_from_slice(&4280u16.to_le_bytes()); // max_xmit_frag
        pdu.extend_from_slice(&4280u16.to_le_bytes()); // max_recv_frag
        pdu.extend_from_slice(&1u32.to_le_bytes()); // assoc_group
        pdu.extend_from_slice(&addr_len.to_le_bytes());
        pdu.extend_from_slice(secondary_addr);
        // Pad to 4-byte boundary (from PDU start) before num_results
        while pdu.len() % 4 != 0 {
            pdu.push(0);
        }
        // results
        pdu.extend_from_slice(&1u32.to_le_bytes()); // num_results + padding
        pdu.extend_from_slice(&0u16.to_le_bytes()); // result: acceptance
        pdu.extend_from_slice(&0u16.to_le_bytes()); // reason
        pdu.extend_from_slice(&ndr_syntax); // transfer syntax UUID
        pdu.extend_from_slice(&2u32.to_le_bytes()); // syntax version

        // Patch frag_length
        let frag_len = pdu.len() as u16;
        pdu[8..10].copy_from_slice(&frag_len.to_le_bytes());
        pdu
    }

    pub(crate) fn dcerpc_request(&self, call_id: u32, input: &[u8]) -> Vec<u8> {
        if input.len() < 24 {
            return Vec::new();
        }
        let opnum = read_u16_le(input, 22);

        let stub = match opnum {
            15 => self.srvsvc_net_share_enum(), // NetShareEnumAll
            _ => {
                log::debug!("DCE/RPC unsupported opnum: {opnum}");
                return Vec::new();
            }
        };

        // DCE/RPC response header
        let frag_len = 24 + stub.len();
        let mut pdu = Vec::with_capacity(frag_len);
        pdu.push(5);
        pdu.push(0);
        pdu.push(2); // response
        pdu.push(0x03); // first+last
        pdu.extend_from_slice(&0x00000010u32.to_le_bytes());
        pdu.extend_from_slice(&(frag_len as u16).to_le_bytes());
        pdu.extend_from_slice(&0u16.to_le_bytes());
        pdu.extend_from_slice(&call_id.to_le_bytes());
        // response body
        pdu.extend_from_slice(&(stub.len() as u32).to_le_bytes()); // alloc_hint
        pdu.extend_from_slice(&0u16.to_le_bytes()); // context_id
        pdu.push(0); // cancel_count
        pdu.push(0); // reserved
        pdu.extend_from_slice(&stub);
        pdu
    }

    /// Build NDR-encoded NetShareEnumAll response (level 1) listing our share.
    pub(crate) fn srvsvc_net_share_enum(&self) -> Vec<u8> {
        let name = &self.share_name;
        let comment = "";

        // Encode UCS-2 strings (with terminating null)
        let name_ucs2: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let comment_ucs2: Vec<u16> = comment.encode_utf16().chain(std::iter::once(0)).collect();

        let mut stub = Vec::with_capacity(128);

        // NetShareInfoCtr struct (level + union)
        stub.extend_from_slice(&1u32.to_le_bytes()); // Level
        stub.extend_from_slice(&1u32.to_le_bytes()); // Switch discriminator
        stub.extend_from_slice(&0x00020000u32.to_le_bytes()); // Ctr1 pointer referent

        // Deferred: NetShareCtr1
        stub.extend_from_slice(&1u32.to_le_bytes()); // Count
        stub.extend_from_slice(&0x00020004u32.to_le_bytes()); // Array pointer referent

        // Deferred: array (conformant)
        stub.extend_from_slice(&1u32.to_le_bytes()); // MaxCount

        // Array elements (SHARE_INFO_1: name_ptr, type, comment_ptr)
        stub.extend_from_slice(&0x00020008u32.to_le_bytes()); // Name pointer referent
        stub.extend_from_slice(&0u32.to_le_bytes()); // Type: STYPE_DISKTREE
        stub.extend_from_slice(&0x0002000Cu32.to_le_bytes()); // Comment pointer referent

        // Deferred strings for element 0: name then comment
        // Name: conformant varying string
        stub.extend_from_slice(&(name_ucs2.len() as u32).to_le_bytes()); // MaxCount
        stub.extend_from_slice(&0u32.to_le_bytes()); // Offset
        stub.extend_from_slice(&(name_ucs2.len() as u32).to_le_bytes()); // ActualCount
        for ch in &name_ucs2 {
            stub.extend_from_slice(&ch.to_le_bytes());
        }
        while stub.len() % 4 != 0 {
            stub.push(0);
        }

        // Comment: conformant varying string
        stub.extend_from_slice(&(comment_ucs2.len() as u32).to_le_bytes());
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub.extend_from_slice(&(comment_ucs2.len() as u32).to_le_bytes());
        for ch in &comment_ucs2 {
            stub.extend_from_slice(&ch.to_le_bytes());
        }
        while stub.len() % 4 != 0 {
            stub.push(0);
        }

        // TotalEntries
        stub.extend_from_slice(&1u32.to_le_bytes());
        // ResumeHandle pointer (null)
        stub.extend_from_slice(&0u32.to_le_bytes());
        // Return value: WERR_OK
        stub.extend_from_slice(&0u32.to_le_bytes());
        stub
    }
}
