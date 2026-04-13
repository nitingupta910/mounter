//! SMB2 protocol types, parsing, and serialization.
//!
//! Implements the subset of MS-SMB2 needed for mount_smbfs / SMB clients:
#![allow(dead_code)] // protocol constants are defined for completeness
//! NEGOTIATE, SESSION_SETUP, TREE_CONNECT, CREATE, CLOSE, READ, WRITE,
//! QUERY_DIRECTORY (FIND), QUERY_INFO, SET_INFO, LOGOFF, TREE_DISCONNECT.

use std::io::{self, Read};

// ── Protocol constants ──────────────────────────────────────────────

pub const SMB2_MAGIC: &[u8; 4] = b"\xfeSMB";
pub const SMB1_MAGIC: &[u8; 4] = b"\xffSMB";
pub const SMB2_HEADER_SIZE: usize = 64;

// Commands
pub const SMB2_NEGOTIATE: u16 = 0x0000;
pub const SMB2_SESSION_SETUP: u16 = 0x0001;
pub const SMB2_LOGOFF: u16 = 0x0002;
pub const SMB2_TREE_CONNECT: u16 = 0x0003;
pub const SMB2_TREE_DISCONNECT: u16 = 0x0004;
pub const SMB2_CREATE: u16 = 0x0005;
pub const SMB2_CLOSE: u16 = 0x0006;
pub const SMB2_FLUSH: u16 = 0x0007;
pub const SMB2_READ: u16 = 0x0008;
pub const SMB2_WRITE: u16 = 0x0009;
pub const SMB2_IOCTL: u16 = 0x000B;
pub const SMB2_QUERY_DIRECTORY: u16 = 0x000E;
pub const SMB2_QUERY_INFO: u16 = 0x0010;
pub const SMB2_SET_INFO: u16 = 0x0011;

// Dialects
pub const SMB2_DIALECT_202: u16 = 0x0202;
pub const SMB2_DIALECT_210: u16 = 0x0210;
pub const SMB2_DIALECT_300: u16 = 0x0300;
pub const SMB2_DIALECT_302: u16 = 0x0302;
pub const SMB2_DIALECT_311: u16 = 0x0311;

// Status codes
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_MORE_PROCESSING: u32 = 0xC000_0016;
pub const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_NO_SUCH_FILE: u32 = 0xC000_000F;
pub const STATUS_END_OF_FILE: u32 = 0xC000_0011;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
pub const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
pub const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
pub const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;

// Header flags
pub const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;

// CREATE dispositions
pub const FILE_SUPERSEDE: u32 = 0;
pub const FILE_OPEN: u32 = 1;
pub const FILE_CREATE: u32 = 2;
pub const FILE_OPEN_IF: u32 = 3;
pub const FILE_OVERWRITE: u32 = 4;
pub const FILE_OVERWRITE_IF: u32 = 5;

// CREATE access mask
pub const FILE_READ_DATA: u32 = 0x0000_0001;
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
pub const DELETE: u32 = 0x0001_0000;
pub const FILE_READ_EA: u32 = 0x0000_0008;
pub const FILE_WRITE_EA: u32 = 0x0000_0010;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

// File attributes
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

// CREATE options
pub const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;

// Share access
pub const FILE_SHARE_READ: u32 = 0x0000_0001;
pub const FILE_SHARE_WRITE: u32 = 0x0000_0002;
pub const FILE_SHARE_DELETE: u32 = 0x0000_0004;

// QUERY_DIRECTORY info levels
pub const FILE_DIRECTORY_INFORMATION: u8 = 1;
pub const FILE_FULL_DIRECTORY_INFORMATION: u8 = 2;
pub const FILE_BOTH_DIRECTORY_INFORMATION: u8 = 3;
pub const FILE_ID_BOTH_DIRECTORY_INFORMATION: u8 = 37;
pub const FILE_ID_FULL_DIRECTORY_INFORMATION: u8 = 38;

// QUERY_INFO info types
pub const SMB2_0_INFO_FILE: u8 = 1;
pub const SMB2_0_INFO_FILESYSTEM: u8 = 2;
pub const SMB2_0_INFO_SECURITY: u8 = 3;

// File info classes
pub const FILE_BASIC_INFORMATION: u8 = 4;
pub const FILE_STANDARD_INFORMATION: u8 = 5;
pub const FILE_INTERNAL_INFORMATION: u8 = 6;
pub const FILE_EA_INFORMATION: u8 = 7;
pub const FILE_NETWORK_OPEN_INFORMATION: u8 = 34;
pub const FILE_ALL_INFORMATION: u8 = 18;
pub const FILE_STREAM_INFORMATION: u8 = 22;
pub const FILE_RENAME_INFORMATION: u8 = 10;
pub const FILE_DISPOSITION_INFORMATION: u8 = 13;
pub const FILE_POSITION_INFORMATION: u8 = 14;
pub const FILE_ATTRIBUTE_TAG_INFORMATION: u8 = 35;

// Filesystem info classes
pub const FS_SIZE_INFORMATION: u8 = 3;
pub const FS_ATTRIBUTE_INFORMATION: u8 = 5;
pub const FS_FULL_SIZE_INFORMATION: u8 = 7;
pub const FS_VOLUME_INFORMATION: u8 = 1;
pub const FS_SECTOR_SIZE_INFORMATION: u8 = 11;

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

// ── Wire helpers ────────────────────────────────────────────────────

pub fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

pub fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

pub fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

/// Check if the given message bytes are an SMB1 negotiate request (magic \xFF SMB).
pub fn is_smb1_negotiate(msg: &[u8]) -> bool {
    msg.len() >= 4 && &msg[0..4] == SMB1_MAGIC
}

/// Build a SPNEGO negTokenInit containing the NTLMSSP OID and the
/// mechListMIC "not_defined_in_RFC4178@please_ignore", matching the
/// exact 74-byte blob that Samba sends in its negotiate responses.
pub fn build_spnego_negotiate_token() -> Vec<u8> {
    // NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
    let ntlmssp_oid = [
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
    ];
    // mechListMIC hint: "not_defined_in_RFC4178@please_ignore"
    let hint_str = b"not_defined_in_RFC4178@please_ignore";

    // negHints [3] SEQUENCE { hintName [0] GeneralString }
    let hint_name_inner = {
        let mut v = Vec::new();
        v.push(0x1b); // GeneralString tag
        asn1_write_length(&mut v, hint_str.len());
        v.extend_from_slice(hint_str);
        v
    };
    let hint_name = asn1_context(0, &hint_name_inner);
    let neg_hints_seq = asn1_sequence(&hint_name);
    let neg_hints = asn1_context(3, &neg_hints_seq);

    // mechTypes [0] SEQUENCE { OID }
    let mech_list = asn1_sequence(&ntlmssp_oid);
    let mech_types = asn1_context(0, &mech_list);

    // NegTokenInit SEQUENCE { mechTypes, negHints }
    let mut neg_token_init_inner = Vec::new();
    neg_token_init_inner.extend_from_slice(&mech_types);
    neg_token_init_inner.extend_from_slice(&neg_hints);
    let neg_token_init = asn1_sequence(&neg_token_init_inner);
    let neg_token = asn1_context(0, &neg_token_init);

    // Wrap in Application [0] with SPNEGO OID
    let spnego_oid = [0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
    let mut wrapper = Vec::new();
    wrapper.extend_from_slice(&spnego_oid);
    wrapper.extend_from_slice(&neg_token);

    let mut result = Vec::new();
    result.push(0x60); // Application [0] CONSTRUCTED
    asn1_write_length(&mut result, wrapper.len());
    result.extend_from_slice(&wrapper);
    result
}

/// Build an SMB2 NEGOTIATE response to an SMB1 negotiate request.
/// This tells the client to upgrade from SMB1 to SMB2.
/// Per MS-SMB2 3.3.5.3.1: the server responds with an SMB2 NEGOTIATE
/// response with DialectRevision = 0x02FF (wildcard) to indicate that
/// the client should re-negotiate using SMB2.
///
/// Matches Samba's negotiate response: SecurityMode=1 (signing enabled),
/// Capabilities=7, 8 MB max sizes, and includes the SPNEGO negTokenInit.
pub fn build_smb1_to_smb2_negotiate_response() -> Vec<u8> {
    let spnego = build_spnego_negotiate_token();

    let mut body = Vec::with_capacity(128 + spnego.len());
    body.extend_from_slice(&65u16.to_le_bytes()); // StructureSize
    body.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode: SIGNING_ENABLED
    body.extend_from_slice(&0x02FFu16.to_le_bytes()); // DialectRevision: SMB2 wildcard
    body.extend_from_slice(&0u16.to_le_bytes()); // Reserved

    // ServerGuid (16 bytes)
    body.extend_from_slice(&[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ]);
    body.extend_from_slice(&7u32.to_le_bytes()); // Capabilities: DFS | LEASING | LARGE_MTU
    body.extend_from_slice(&(8 * 1024 * 1024u32).to_le_bytes()); // MaxTransactSize: 8 MB
    body.extend_from_slice(&(8 * 1024 * 1024u32).to_le_bytes()); // MaxReadSize: 8 MB
    body.extend_from_slice(&(8 * 1024 * 1024u32).to_le_bytes()); // MaxWriteSize: 8 MB
    body.extend_from_slice(&0u64.to_le_bytes()); // SystemTime
    body.extend_from_slice(&0u64.to_le_bytes()); // ServerStartTime

    // SecurityBuffer at offset 128 from start of SMB2 header (64 hdr + 64 body fields)
    body.extend_from_slice(&128u16.to_le_bytes()); // SecurityBufferOffset
    body.extend_from_slice(&(spnego.len() as u16).to_le_bytes()); // SecurityBufferLength
    body.extend_from_slice(&0u32.to_le_bytes()); // Reserved2

    // Append the SPNEGO security blob
    body.extend_from_slice(&spnego);

    let total = SMB2_HEADER_SIZE + body.len();
    let mut out = Vec::with_capacity(4 + total);

    // NetBIOS session header
    out.extend_from_slice(&(total as u32).to_be_bytes());

    // SMB2 header for the negotiate response
    out.extend_from_slice(SMB2_MAGIC); // 0-3:   ProtocolId
    out.extend_from_slice(&64u16.to_le_bytes()); // 4-5:   StructureSize
    out.extend_from_slice(&0u16.to_le_bytes()); // 6-7:   CreditCharge
    out.extend_from_slice(&0u32.to_le_bytes()); // 8-11:  Status: SUCCESS
    out.extend_from_slice(&SMB2_NEGOTIATE.to_le_bytes()); // 12-13: Command: NEGOTIATE
    out.extend_from_slice(&1u16.to_le_bytes()); // 14-15: CreditResponse
    let flags = SMB2_FLAGS_SERVER_TO_REDIR;
    out.extend_from_slice(&flags.to_le_bytes()); // 16-19: Flags
    out.extend_from_slice(&0u32.to_le_bytes()); // 20-23: NextCommand
    out.extend_from_slice(&0u64.to_le_bytes()); // 24-31: MessageId
    out.extend_from_slice(&0u32.to_le_bytes()); // 32-35: Reserved
    out.extend_from_slice(&0u32.to_le_bytes()); // 36-39: TreeId
    out.extend_from_slice(&0u64.to_le_bytes()); // 40-47: SessionId
    out.extend_from_slice(&[0u8; 16]); // 48-63: Signature

    out.extend_from_slice(&body);
    out
}

/// Read an SMB message from a TCP stream (NetBIOS framing).
/// Returns the raw message bytes (without the 4-byte length prefix).
pub fn read_message(stream: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 16 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad SMB message length",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Format a hex dump of the first `max_bytes` bytes of data (for debug logging).
pub fn hex_dump(data: &[u8], max_bytes: usize) -> String {
    use std::fmt::Write;
    let limit = data.len().min(max_bytes);
    let mut s = String::new();
    for (i, chunk) in data[..limit].chunks(16).enumerate() {
        let _ = write!(s, "\n  {:04x}: ", i * 16);
        for (j, byte) in chunk.iter().enumerate() {
            let _ = write!(s, "{:02x} ", byte);
            if j == 7 {
                s.push(' ');
            }
        }
        // Pad to align ASCII column
        let pad = 16 - chunk.len();
        for _ in 0..pad {
            s.push_str("   ");
        }
        if pad > 8 {
            s.push(' ');
        }
        s.push_str(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                s.push(*byte as char);
            } else {
                s.push('.');
            }
        }
        s.push('|');
    }
    if data.len() > limit {
        let _ = write!(s, "\n  ... ({} more bytes)", data.len() - limit);
    }
    s
}

/// Encode a UTF-16LE string (for SMB wire format).
pub fn to_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

/// Decode a UTF-16LE string from SMB wire format.
pub fn from_utf16le(data: &[u8]) -> String {
    let chars: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&chars)
}

/// Windows FILETIME (100-ns intervals since 1601-01-01) from Unix timestamp.
pub fn unix_to_filetime(secs: u64) -> u64 {
    // Offset between 1601-01-01 and 1970-01-01 in 100-ns intervals
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    secs.saturating_mul(10_000_000).saturating_add(EPOCH_DIFF)
}

/// Unix timestamp from Windows FILETIME.
pub fn filetime_to_unix(ft: u64) -> u64 {
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    ft.saturating_sub(EPOCH_DIFF) / 10_000_000
}

// ── NTLMSSP (minimal guest authentication) ──────────────────────────

/// Wrap NTLMSSP in a GSS/SPNEGO blob for SESSION_SETUP response.
pub fn wrap_ntlmssp_in_spnego(ntlmssp: &[u8]) -> Vec<u8> {
    let oid = [
        0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
    ]; // NTLMSSP OID

    // responseToken [2] OCTET STRING
    let resp_token = asn1_context(2, &asn1_octet_string(ntlmssp));
    // supportedMech [1] OID
    let supported_mech = asn1_context(1, &oid);
    // negResult [0] ENUMERATED = accept-incomplete (1)
    let neg_result = asn1_context(0, &[0x0a, 0x01, 0x01]);

    let neg_token_resp_inner = [neg_result, supported_mech, resp_token].concat();
    let neg_token_resp = asn1_sequence(&neg_token_resp_inner);
    let neg_token_targ = asn1_context(1, &neg_token_resp);

    neg_token_targ
}

/// Final SPNEGO accept-complete token.
pub fn spnego_accept_complete() -> Vec<u8> {
    let neg_result = asn1_context(0, &[0x0a, 0x01, 0x00]); // accept-completed
    let neg_token_resp = asn1_sequence(&neg_result);
    asn1_context(1, &neg_token_resp)
}

pub fn asn1_context(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xa0 | tag);
    asn1_write_length(&mut out, data.len());
    out.extend_from_slice(data);
    out
}

pub fn asn1_sequence(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x30);
    asn1_write_length(&mut out, data.len());
    out.extend_from_slice(data);
    out
}

pub fn asn1_octet_string(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0x04);
    asn1_write_length(&mut out, data.len());
    out.extend_from_slice(data);
    out
}

pub fn asn1_write_length(out: &mut Vec<u8>, len: usize) {
    if len < 128 {
        out.push(len as u8);
    } else if len < 256 {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf16le_roundtrip() {
        let s = "hello.txt";
        let encoded = to_utf16le(s);
        assert_eq!(encoded.len(), s.len() * 2);
        assert_eq!(from_utf16le(&encoded), s);
    }

    #[test]
    fn filetime_roundtrip() {
        let now = 1700000000u64; // ~2023
        let ft = unix_to_filetime(now);
        let back = filetime_to_unix(ft);
        assert_eq!(back, now);
    }

    #[test]
    fn filetime_epoch() {
        let ft = unix_to_filetime(0);
        assert_eq!(ft, 116_444_736_000_000_000);
    }

    #[test]
    fn header_parse_valid() {
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(SMB2_MAGIC);
        buf[12] = 0x05; // CREATE command
        let hdr = Smb2Header::parse(&buf);
        assert!(hdr.is_some());
        assert_eq!(hdr.as_ref().map(|h| h.command), Some(SMB2_CREATE));
    }

    #[test]
    fn header_parse_bad_magic() {
        let buf = [0u8; 64];
        assert!(Smb2Header::parse(&buf).is_none());
    }

    #[test]
    fn header_parse_short() {
        let buf = [0u8; 32];
        assert!(Smb2Header::parse(&buf).is_none());
    }

}
