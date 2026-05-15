//! SMB1 upgrade and negotiate helpers.

use super::constants::{
    SMB1_MAGIC, SMB2_FLAGS_SERVER_TO_REDIR, SMB2_HEADER_SIZE, SMB2_MAGIC, SMB2_NEGOTIATE,
};
use super::spnego::{asn1_context, asn1_sequence, asn1_write_length};

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
