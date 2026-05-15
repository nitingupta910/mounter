//! SMB2 message header.

use super::constants::*;

// ── SMB2 Header ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Smb2Header {
    pub command: u16,
    pub status: u32,
    pub flags: u32,
    pub message_id: u64,
    pub session_id: u64,
    pub tree_id: u32,
    pub credit_charge: u16,
    pub credits_requested: u16,
}

impl Smb2Header {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < SMB2_HEADER_SIZE {
            return None;
        }
        if &buf[0..4] != SMB2_MAGIC {
            return None;
        }
        Some(Smb2Header {
            command: u16::from_le_bytes([buf[12], buf[13]]),
            status: u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]),
            flags: u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]),
            message_id: u64::from_le_bytes([
                buf[24], buf[25], buf[26], buf[27], buf[28], buf[29], buf[30], buf[31],
            ]),
            credit_charge: u16::from_le_bytes([buf[6], buf[7]]),
            credits_requested: u16::from_le_bytes([buf[14], buf[15]]),
            session_id: u64::from_le_bytes([
                buf[40], buf[41], buf[42], buf[43], buf[44], buf[45], buf[46], buf[47],
            ]),
            tree_id: u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]),
        })
    }

    pub fn write_response(&self, status: u32, body: &[u8], out: &mut Vec<u8>) {
        let total = SMB2_HEADER_SIZE + body.len();

        // NetBIOS session header (4 bytes: length as big-endian u32)
        out.extend_from_slice(&(total as u32).to_be_bytes());

        // SMB2 header (64 bytes) — MS-SMB2 2.2.1
        out.extend_from_slice(SMB2_MAGIC); // 0-3:   ProtocolId
        out.extend_from_slice(&64u16.to_le_bytes()); // 4-5:   StructureSize
        out.extend_from_slice(&1u16.to_le_bytes()); // 6-7:   CreditCharge
        out.extend_from_slice(&status.to_le_bytes()); // 8-11:  Status
        out.extend_from_slice(&self.command.to_le_bytes()); // 12-13: Command
        let credits_granted = self.credits_requested.max(1);
        out.extend_from_slice(&credits_granted.to_le_bytes()); // 14-15: CreditResponse
        let flags = SMB2_FLAGS_SERVER_TO_REDIR;
        out.extend_from_slice(&flags.to_le_bytes()); // 16-19: Flags
        out.extend_from_slice(&0u32.to_le_bytes()); // 20-23: NextCommand
        out.extend_from_slice(&self.message_id.to_le_bytes()); // 24-31: MessageId
        out.extend_from_slice(&0u32.to_le_bytes()); // 32-35: Reserved
        out.extend_from_slice(&self.tree_id.to_le_bytes()); // 36-39: TreeId
        out.extend_from_slice(&self.session_id.to_le_bytes()); // 40-47: SessionId
        out.extend_from_slice(&[0u8; 16]); // 48-63: Signature

        out.extend_from_slice(body);
    }
}
