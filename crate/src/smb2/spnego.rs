//! SPNEGO / ASN.1 helpers for NTLM session setup.

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
