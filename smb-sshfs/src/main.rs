//! smb-sshfs: Single-binary SSH mount for macOS.
//!
//! Combines an SMB2 server + SFTP client in one process.
//! macOS mounts via `mount_smbfs`, all file ops go directly to SSH.
//! No Docker, no Samba, no FUSE, no sudo.

mod server;
mod sftp;
mod smb2;

use server::SmbSession;
use sftp::SftpSession;
use std::env;
use std::io::Write;
use std::net::TcpListener;
use std::process;
use std::sync::Arc;

fn usage() -> ! {
    eprintln!("smb-sshfs — mount remote SSH directories in Finder");
    eprintln!();
    eprintln!("Usage: smb-sshfs [user@]host:[path] [options]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -p PORT         SSH port (default: 22)");
    eprintln!("  -i IDENTITY     SSH identity file");
    eprintln!("  -n NAME         Share name (default: host)");
    eprintln!("  --smb-port PORT Local SMB port (default: auto)");
    eprintln!();
    eprintln!("After starting, mount with:");
    eprintln!("  mount_smbfs //guest@localhost:<port>/<name> ~/mnt/<name>");
    process::exit(1);
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }

    let remote = &args[1];
    let mut ssh_port: u16 = 22;
    let mut identity: Option<String> = None;
    let mut share_name: Option<String> = None;
    let mut smb_port: u16 = 0; // 0 = auto-assign

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "-p" => {
                i += 1;
                ssh_port = match args.get(i) {
                    Some(s) => match s.parse() {
                        Ok(p) => p,
                        Err(_) => {
                            eprintln!("invalid port: {s}");
                            process::exit(1);
                        }
                    },
                    None => {
                        eprintln!("missing port after -p");
                        process::exit(1);
                    }
                };
            }
            "-i" => {
                i += 1;
                identity = args.get(i).cloned();
            }
            "-n" => {
                i += 1;
                share_name = args.get(i).cloned();
            }
            "--smb-port" => {
                i += 1;
                smb_port = match args.get(i) {
                    Some(s) => match s.parse() {
                        Ok(p) => p,
                        Err(_) => {
                            eprintln!("invalid SMB port: {s}");
                            process::exit(1);
                        }
                    },
                    None => {
                        eprintln!("missing port after --smb-port");
                        process::exit(1);
                    }
                };
            }
            "-h" | "--help" => usage(),
            other => {
                eprintln!("unknown option: {other}");
                usage();
            }
        }
        i += 1;
    }

    // Parse remote spec
    let (user, host, remote_path) = parse_remote(remote);
    let name = share_name.unwrap_or_else(|| host.clone());

    // Connect via SFTP
    log::info!("Connecting to {host}:{ssh_port}...");
    let sftp = match SftpSession::connect(&host, ssh_port, user.as_deref(), identity.as_deref()) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("SSH connection failed: {e}");
            process::exit(1);
        }
    };

    // Resolve remote path
    let root = if remote_path.is_empty() || remote_path == "." {
        match sftp.realpath(".") {
            Ok(p) => p,
            Err(e) => {
                eprintln!("realpath failed: {e}");
                process::exit(1);
            }
        }
    } else {
        match sftp.realpath(&remote_path) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("realpath '{remote_path}' failed: {e}");
                process::exit(1);
            }
        }
    };

    log::info!("Remote root: {root}");

    // Start SMB2 server
    let listener = match TcpListener::bind(format!("127.0.0.1:{smb_port}")) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind SMB port: {e}");
            process::exit(1);
        }
    };
    let local_port = listener.local_addr().map(|a| a.port()).unwrap_or(0);

    log::info!("SMB server listening on 127.0.0.1:{local_port}");
    println!("Mount with:");
    println!("  mount_smbfs //guest@localhost:{local_port}/{name} ~/mnt/{name}");

    // Accept connections (single-threaded — one macOS client)
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                log::info!(
                    "Client connected: {}",
                    stream
                        .peer_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_default()
                );
                let mut session = SmbSession::new(Arc::clone(&sftp), root.clone(), name.clone());

                loop {
                    let msg = match smb2::read_message(&mut stream) {
                        Ok(m) => m,
                        Err(e) => {
                            log::debug!("Connection closed: {e}");
                            break;
                        }
                    };

                    // Log raw bytes received for debugging
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
                        continue; // Next message should be a proper SMB2 negotiate
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
                        // Single command — simple path
                        let response = session.handle_message(&msg);
                        if !response.is_empty() {
                            if let Err(e) = stream.write_all(&response) {
                                log::debug!("Write: {e}");
                                break;
                            }
                        }
                    } else {
                        // Compound — collect response bodies (strip NetBIOS headers),
                        // set NextCommand, wrap in single NetBIOS frame.
                        let mut resp_bodies: Vec<Vec<u8>> = Vec::new();
                        for (i, (start, end)) in cmd_offsets.iter().enumerate() {
                            let single = &msg[*start..*end];
                            let cmd_code = smb2::read_u16_le(single, 12);
                            log::info!(
                                "  Compound[{i}]: cmd=0x{cmd_code:04x} len={}",
                                single.len()
                            );
                            let resp = session.handle_message(single);
                            // Strip 4-byte NetBIOS header
                            if resp.len() > 4 {
                                resp_bodies.push(resp[4..].to_vec());
                            }
                        }

                        // Set NextCommand offsets and combine
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

                        // Single NetBIOS frame for all responses
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
            Err(e) => log::warn!("Accept error: {e}"),
        }
    }
}

fn parse_remote(spec: &str) -> (Option<String>, String, String) {
    let mut rest = spec.to_string();
    let mut user = None;
    if let Some(at) = rest.find('@') {
        user = Some(rest[..at].to_string());
        rest = rest[at + 1..].to_string();
    }
    if let Some(colon) = rest.find(':') {
        let host = rest[..colon].to_string();
        let path = rest[colon + 1..].to_string();
        (user, host, path)
    } else {
        (user, rest, String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_remote_full() {
        let (u, h, p) = parse_remote("alice@host:/data");
        assert_eq!(u, Some("alice".to_string()));
        assert_eq!(h, "host");
        assert_eq!(p, "/data");
    }

    #[test]
    fn parse_remote_no_user() {
        let (u, h, p) = parse_remote("host:/data");
        assert_eq!(u, None);
        assert_eq!(h, "host");
        assert_eq!(p, "/data");
    }

    #[test]
    fn parse_remote_host_only() {
        let (u, h, p) = parse_remote("host");
        assert_eq!(u, None);
        assert_eq!(h, "host");
        assert_eq!(p, "");
    }
}
