//! Per-client SMB2 connection handler.

use crate::server::SmbSession;
use crate::sftp::ReconnectingSftp;
use crate::smb2;
use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;

pub(crate) fn handle_client(
    mut stream: TcpStream,
    sftp: Arc<ReconnectingSftp>,
    root: String,
    name: String,
    smb_user: String,
) {
    let _ = stream.set_nodelay(true);
    log::info!(
        "Client connected: {}",
        stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_default()
    );
    let mut session = SmbSession::new(sftp, root, name, smb_user);

    loop {
        let msg = match smb2::read_message(&mut stream) {
            Ok(m) => m,
            Err(e) => {
                log::debug!("Connection closed: {e}");
                break;
            }
        };

        log::debug!("Received {} bytes:{}", msg.len(), smb2::hex_dump(&msg, 128));

        // Check for SMB1 negotiate (macOS sends \xFF SMB first)
        if smb2::is_smb1_negotiate(&msg) {
            log::info!("Received SMB1 negotiate — responding with SMB2 upgrade");
            let response = smb2::build_smb1_to_smb2_negotiate_response();
            if let Err(e) = stream.write_all(&response) {
                log::debug!("Write error: {e}");
                break;
            }
            if let Err(e) = stream.flush() {
                log::debug!("Flush error: {e}");
                break;
            }
            continue;
        }

        // Handle compounded requests — macOS sends multiple
        // SMB2 commands in one TCP message (NextCommand field).
        // Compound responses must be in a SINGLE NetBIOS frame.
        let mut cmd_offsets = Vec::new();
        let mut offset = 0;
        while offset < msg.len() {
            if msg.len() - offset < smb2::SMB2_HEADER_SIZE {
                break;
            }
            let next_cmd = smb2::read_u32_le(&msg[offset..], 20) as usize;
            let cmd_end = if next_cmd > 0 {
                offset + next_cmd
            } else {
                msg.len()
            };
            cmd_offsets.push((offset, cmd_end));
            if next_cmd == 0 {
                break;
            }
            offset += next_cmd;
        }

        if cmd_offsets.len() <= 1 {
            let response = session.handle_message(&msg);
            if !response.is_empty() {
                if let Err(e) = stream.write_all(&response) {
                    log::debug!("Write: {e}");
                    break;
                }
            }
        } else {
            let mut resp_bodies: Vec<Vec<u8>> = Vec::new();
            for (i, (start, end)) in cmd_offsets.iter().enumerate() {
                let single = &msg[*start..*end];
                let cmd_code = smb2::read_u16_le(single, 12);
                log::debug!("  Compound[{i}]: cmd=0x{cmd_code:04x} len={}", single.len());
                let resp = session.handle_message(single);
                if resp.len() > 4 {
                    resp_bodies.push(resp[4..].to_vec());
                }
            }

            let count = resp_bodies.len();
            let mut combined = Vec::new();
            for i in 0..count {
                if i < count - 1 {
                    while resp_bodies[i].len() % 8 != 0 {
                        resp_bodies[i].push(0);
                    }
                    let next = resp_bodies[i].len() as u32;
                    resp_bodies[i][20..24].copy_from_slice(&next.to_le_bytes());
                }
                combined.extend_from_slice(&resp_bodies[i]);
            }

            let frame_len = (combined.len() as u32).to_be_bytes();
            if let Err(e) = stream.write_all(&frame_len) {
                log::debug!("Write: {e}");
                break;
            }
            if let Err(e) = stream.write_all(&combined) {
                log::debug!("Write: {e}");
                break;
            }
        }
        if let Err(e) = stream.flush() {
            log::debug!("Flush: {e}");
            break;
        }
    }
    log::info!("Client disconnected");
}
