//! SMB2 command handlers.

use super::super::session::SmbSession;
use crate::smb2::*;
use std::time::{SystemTime, UNIX_EPOCH};

impl SmbSession {
    // ── NEGOTIATE ───────────────────────────────────────────────────

    pub(crate) fn handle_negotiate(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        // Parse client's requested dialects to pick the best one
        let dialect_count = if body.len() >= 4 {
            read_u16_le(body, 2) as usize
        } else {
            0
        };
        // Force SMB 2.0.2 — simplest dialect, no signing needed for guest.
        // SMB 3.x requires signing which breaks unsigned guest sessions.
        let _ = dialect_count;
        let best_dialect = SMB2_DIALECT_202;
        log::info!("Negotiated dialect: 0x{:04x}", best_dialect);

        let spnego = build_spnego_negotiate_token();

        let mut resp = Vec::with_capacity(128 + spnego.len());
        resp.extend_from_slice(&65u16.to_le_bytes()); // StructureSize
        resp.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode: SIGNING_ENABLED
        resp.extend_from_slice(&best_dialect.to_le_bytes()); // DialectRevision
        resp.extend_from_slice(&0u16.to_le_bytes()); // Reserved

        // ServerGuid (16 bytes)
        resp.extend_from_slice(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        resp.extend_from_slice(&7u32.to_le_bytes()); // Capabilities: DFS | LEASING | LARGE_MTU
        resp.extend_from_slice(&(8 * 1024 * 1024u32).to_le_bytes()); // MaxTransactSize: 8 MB
        resp.extend_from_slice(&(8 * 1024 * 1024u32).to_le_bytes()); // MaxReadSize: 8 MB
        resp.extend_from_slice(&(8 * 1024 * 1024u32).to_le_bytes()); // MaxWriteSize: 8 MB

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        resp.extend_from_slice(&unix_to_filetime(now).to_le_bytes()); // SystemTime
        resp.extend_from_slice(&unix_to_filetime(now).to_le_bytes()); // ServerStartTime

        // SecurityBuffer at offset 128 from start of SMB2 header (64 hdr + 64 body fields)
        resp.extend_from_slice(&128u16.to_le_bytes()); // SecurityBufferOffset
        resp.extend_from_slice(&(spnego.len() as u16).to_le_bytes()); // SecurityBufferLength
        resp.extend_from_slice(&0u32.to_le_bytes()); // Reserved2
        resp.extend_from_slice(&spnego);

        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── SESSION_SETUP ───────────────────────────────────────────────

    pub(crate) fn handle_session_setup(
        &mut self,
        hdr: &Smb2Header,
        body: &[u8],
        out: &mut Vec<u8>,
    ) {
        self.auth_phase += 1;
        log::info!("SESSION_SETUP phase {}", self.auth_phase);

        // Extract client's security buffer (SPNEGO wrapping NTLMSSP)
        // MS-SMB2 2.2.5: SecurityBufferOffset at body[12], Length at body[14]
        let sec_offset = if body.len() >= 14 {
            read_u16_le(body, 12) as usize
        } else {
            0
        };
        let sec_length = if body.len() >= 16 {
            read_u16_le(body, 14) as usize
        } else {
            0
        };
        let sec_start = sec_offset.saturating_sub(SMB2_HEADER_SIZE);
        let sec_data = if sec_start + sec_length <= body.len() {
            &body[sec_start..sec_start + sec_length]
        } else {
            &[]
        };

        // Detect NTLMSSP message type inside SPNEGO wrapper
        let ntlmssp = ntlmssp_message(sec_data);
        let ntlmssp_type = ntlmssp.map(ntlmssp_message_type);

        log::info!(
            "SESSION_SETUP: sec_offset={sec_offset} sec_length={sec_length} ntlmssp_type={:?}",
            ntlmssp_type
        );

        if ntlmssp_type == Some(1) {
            // Phase 1: extract client's NTLMSSP flags, build matching challenge

            // Find client's negotiate flags
            let client_flags = sec_data
                .windows(12)
                .find(|w| w.starts_with(b"NTLMSSP\0"))
                .and_then(|w| {
                    if w.len() >= 16 {
                        Some(u32::from_le_bytes([w[12], w[13], w[14], w[15]]))
                    } else {
                        None
                    }
                })
                .unwrap_or(0xe2088233);

            // Build NTLMSSP_CHALLENGE with TargetInfo (required by Linux CIFS).
            // Flags: echo client flags, remove VERSION, add TARGET_TYPE_SERVER + TARGET_INFO.
            let server_flags = (client_flags & !0x02000000) | 0x00020000 | 0x00800000;

            // Build TargetInfo AV_PAIRs (required by Linux kernel CIFS driver)
            let target_name_utf16 = to_utf16le("SSHFS");
            let mut target_info = Vec::with_capacity(64);
            // MsvAvNbDomainName (2) = "SSHFS"
            target_info.extend_from_slice(&2u16.to_le_bytes());
            target_info.extend_from_slice(&(target_name_utf16.len() as u16).to_le_bytes());
            target_info.extend_from_slice(&target_name_utf16);
            // MsvAvNbComputerName (1) = "SSHFS"
            target_info.extend_from_slice(&1u16.to_le_bytes());
            target_info.extend_from_slice(&(target_name_utf16.len() as u16).to_le_bytes());
            target_info.extend_from_slice(&target_name_utf16);
            // MsvAvDnsDomainName (4) = ""
            target_info.extend_from_slice(&4u16.to_le_bytes());
            target_info.extend_from_slice(&0u16.to_le_bytes());
            // MsvAvDnsComputerName (3) = "sshfs"
            let dns_name = to_utf16le("sshfs");
            target_info.extend_from_slice(&3u16.to_le_bytes());
            target_info.extend_from_slice(&(dns_name.len() as u16).to_le_bytes());
            target_info.extend_from_slice(&dns_name);
            // MsvAvTimestamp (7) = current FILETIME
            let now_ft = unix_to_filetime(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );
            target_info.extend_from_slice(&7u16.to_le_bytes());
            target_info.extend_from_slice(&8u16.to_le_bytes());
            target_info.extend_from_slice(&now_ft.to_le_bytes());
            // MsvAvEOL (0) — terminator
            target_info.extend_from_slice(&0u16.to_le_bytes());
            target_info.extend_from_slice(&0u16.to_le_bytes());

            // Fixed header is 48 bytes, TargetName starts at 48, TargetInfo after that
            let target_name_offset = 48u32;
            let target_info_offset = target_name_offset + target_name_utf16.len() as u32;

            let mut challenge =
                Vec::with_capacity(48 + target_name_utf16.len() + target_info.len());
            challenge.extend_from_slice(b"NTLMSSP\0"); // 0: Signature
            challenge.extend_from_slice(&2u32.to_le_bytes()); // 8: Type=CHALLENGE
            // TargetName fields
            challenge.extend_from_slice(&(target_name_utf16.len() as u16).to_le_bytes()); // 12
            challenge.extend_from_slice(&(target_name_utf16.len() as u16).to_le_bytes()); // 14
            challenge.extend_from_slice(&target_name_offset.to_le_bytes()); // 16
            challenge.extend_from_slice(&server_flags.to_le_bytes()); // 20: NegotiateFlags
            // ServerChallenge (8 bytes)
            challenge.extend_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]); // 24
            challenge.extend_from_slice(&[0u8; 8]); // 32: Reserved
            // TargetInfo fields
            challenge.extend_from_slice(&(target_info.len() as u16).to_le_bytes()); // 40
            challenge.extend_from_slice(&(target_info.len() as u16).to_le_bytes()); // 42
            challenge.extend_from_slice(&target_info_offset.to_le_bytes()); // 44
            // Payload: TargetName + TargetInfo
            challenge.extend_from_slice(&target_name_utf16);
            challenge.extend_from_slice(&target_info);

            log::info!(
                "NTLMSSP challenge: client_flags=0x{client_flags:08x} server_flags=0x{server_flags:08x}"
            );

            // Wrap in SPNEGO negTokenResp
            let spnego = wrap_ntlmssp_in_spnego(&challenge);

            let mut resp = Vec::with_capacity(16 + spnego.len());
            resp.extend_from_slice(&9u16.to_le_bytes());
            resp.extend_from_slice(&0u16.to_le_bytes()); // SessionFlags: 0
            let sec_off = (SMB2_HEADER_SIZE + 8) as u16;
            resp.extend_from_slice(&sec_off.to_le_bytes());
            resp.extend_from_slice(&(spnego.len() as u16).to_le_bytes());
            resp.extend_from_slice(&spnego);

            let mut full_hdr = hdr.clone();
            full_hdr.session_id = self.session_id;
            full_hdr.write_response(STATUS_MORE_PROCESSING, &resp, out);

            log::info!("Sent NTLMSSP challenge in SPNEGO ({} bytes)", spnego.len());
            // Dump the SPNEGO for debugging
            log::debug!("SPNEGO challenge hex: {}", hex_dump(&spnego, 128));
        } else if ntlmssp_type == Some(3)
            && ntlmssp
                .and_then(ntlmssp_auth_username)
                .is_some_and(|user| user == self.smb_user)
        {
            // Phase 2: accept only the per-process SMB user generated at startup.
            let accept = spnego_accept_complete();

            let mut resp = Vec::with_capacity(16 + accept.len());
            resp.extend_from_slice(&9u16.to_le_bytes());
            resp.extend_from_slice(&0u16.to_le_bytes()); // SessionFlags: authenticated
            let sec_off = (SMB2_HEADER_SIZE + 8) as u16;
            resp.extend_from_slice(&sec_off.to_le_bytes());
            resp.extend_from_slice(&(accept.len() as u16).to_le_bytes());
            resp.extend_from_slice(&accept);

            let mut full_hdr = hdr.clone();
            full_hdr.session_id = self.session_id;
            full_hdr.write_response(STATUS_SUCCESS, &resp, out);
            log::info!(
                "Session accepted for generated SMB user (phase {})",
                self.auth_phase
            );
            self.auth_phase = 0;
        } else {
            log::warn!("SESSION_SETUP rejected unauthenticated SMB client");
            self.error_response(hdr, STATUS_LOGON_FAILURE, out);
            self.auth_phase = 0;
        }
    }

    // ── LOGOFF ──────────────────────────────────────────────────────

    pub(crate) fn handle_logoff(&mut self, hdr: &Smb2Header, out: &mut Vec<u8>) {
        let mut resp = Vec::with_capacity(4);
        resp.extend_from_slice(&4u16.to_le_bytes()); // StructureSize
        resp.extend_from_slice(&0u16.to_le_bytes()); // Reserved
        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── TREE_CONNECT ────────────────────────────────────────────────

    pub(crate) fn handle_tree_connect(&mut self, hdr: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
        // Parse the share path from the request (\\server\share in UTF-16LE)
        let mut is_ipc = false;
        if body.len() >= 8 {
            let path_offset = read_u16_le(body, 4) as usize;
            let path_length = read_u16_le(body, 6) as usize;
            let path_start = path_offset.saturating_sub(SMB2_HEADER_SIZE);
            if path_start + path_length <= body.len() {
                let path = from_utf16le(&body[path_start..path_start + path_length]);
                is_ipc = path.to_ascii_uppercase().ends_with("\\IPC$");
            }
        }

        let (share_type, tid) = if is_ipc {
            let tid = self.next_tree_id;
            self.next_tree_id += 1;
            self.ipc_tree_id = Some(tid);
            log::debug!("Tree connected: IPC$ (tid={tid})");
            (0x02u8, tid) // ShareType: PIPE
        } else {
            log::debug!("Tree connected: share={}", self.share_name);
            (0x01u8, self.tree_id) // ShareType: DISK
        };

        let mut resp = Vec::with_capacity(16);
        resp.extend_from_slice(&16u16.to_le_bytes()); // StructureSize
        resp.push(share_type);
        resp.push(0); // Reserved
        resp.extend_from_slice(&0x0000_0030u32.to_le_bytes()); // ShareFlags
        resp.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
        resp.extend_from_slice(&0x001F01FFu32.to_le_bytes()); // MaximalAccess

        let mut full_hdr = hdr.clone();
        full_hdr.tree_id = tid;
        full_hdr.write_response(STATUS_SUCCESS, &resp, out);
    }

    // ── TREE_DISCONNECT ─────────────────────────────────────────────

    pub(crate) fn handle_tree_disconnect(&mut self, hdr: &Smb2Header, out: &mut Vec<u8>) {
        let mut resp = Vec::with_capacity(4);
        resp.extend_from_slice(&4u16.to_le_bytes());
        resp.extend_from_slice(&0u16.to_le_bytes());
        hdr.write_response(STATUS_SUCCESS, &resp, out);
    }
}

fn ntlmssp_message(sec_data: &[u8]) -> Option<&[u8]> {
    let start = sec_data.windows(8).position(|w| w == b"NTLMSSP\0")?;
    Some(&sec_data[start..])
}

fn ntlmssp_message_type(ntlmssp: &[u8]) -> u32 {
    if ntlmssp.len() < 12 {
        return 0;
    }
    u32::from_le_bytes([ntlmssp[8], ntlmssp[9], ntlmssp[10], ntlmssp[11]])
}

fn ntlmssp_auth_username(ntlmssp: &[u8]) -> Option<String> {
    if ntlmssp.len() < 44 || ntlmssp_message_type(ntlmssp) != 3 {
        return None;
    }
    let len = read_u16_le(ntlmssp, 36) as usize;
    let off = read_u32_le(ntlmssp, 40) as usize;
    if len == 0 || off.checked_add(len)? > ntlmssp.len() {
        return None;
    }
    Some(from_utf16le(&ntlmssp[off..off + len]))
}
