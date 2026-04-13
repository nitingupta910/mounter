//! mounter: Single-binary SSH mount for macOS.
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
    eprintln!("mounter — mount remote SSH directories via SMB2-over-SFTP");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  mounter mount [user@]host:[path] [opts]  Mount and run (Ctrl-C to unmount)");
    eprintln!("  mounter [user@]host:[path] [opts]        Start SMB server only");
    eprintln!("  mounter unmount <name|path|all>           Unmount cleanly");
    eprintln!("  mounter list                              Show active mounts");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -p PORT         SSH port (default: 22)");
    eprintln!("  -i IDENTITY     SSH identity file");
    eprintln!("  -n NAME         Share name (default: host)");
    eprintln!("  --smb-port PORT Local SMB port (default: auto)");
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

    // Subcommands
    let auto_mount = args[1] == "mount";
    match args[1].as_str() {
        "unmount" | "umount" => {
            let target = args.get(2).map(|s| s.as_str()).unwrap_or_else(|| {
                eprintln!("Usage: mounter unmount <name|path|all>");
                process::exit(1);
            });
            process::exit(cmd_unmount(target));
        }
        "list" | "ls" => {
            cmd_list();
            process::exit(0);
        }
        "-h" | "--help" | "help" => usage(),
        _ => {}
    }

    // For "mount" subcommand, shift args: mounter mount user@host:path → remote is args[2]
    let remote_idx = if auto_mount { 2 } else { 1 };
    let remote = match args.get(remote_idx) {
        Some(r) => r,
        None => {
            eprintln!("Missing remote spec. Usage: mounter mount [user@]host:[path]");
            process::exit(1);
        }
    };
    let opt_start = remote_idx + 1;
    let mut ssh_port: u16 = 22;
    let mut identity: Option<String> = None;
    let mut share_name: Option<String> = None;
    let mut smb_port: u16 = 0; // 0 = auto-assign

    let mut i = opt_start;
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

    if auto_mount {
        // Spawn mount in background — it will connect once accept loop starts
        spawn_mount(local_port, &name);
        println!("Press Ctrl-C to stop. Clean up with: mounter unmount {name}");
    } else {
        println!("Mount with:");
        println!("  {}", mount_cmd_hint(local_port, &name));
    }

    // Accept connections (single-threaded — one client at a time)
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let _ = stream.set_nodelay(true); // avoid Nagle latency
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

// ── Platform-aware mount/unmount ────────────────────────────────────

use std::process::Command;

fn is_macos() -> bool {
    cfg!(target_os = "macos")
}

fn mount_cmd_hint(port: u16, name: &str) -> String {
    if is_macos() {
        format!("mount_smbfs //guest@localhost:{port}/{name} ~/mnt/{name}")
    } else {
        format!("sudo mount -t cifs //127.0.0.1/{name} ~/mnt/{name} -o guest,vers=2.0,port={port}")
    }
}

/// Spawn the mount command in the background (non-blocking).
/// The mount will complete once the SMB server starts accepting connections.
fn spawn_mount(port: u16, name: &str) -> String {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let mount_point = format!("{home}/mnt/{name}");
    let _ = std::fs::create_dir_all(&mount_point);

    let mp = mount_point.clone();
    let name = name.to_string();
    std::thread::spawn(move || {
        let ok = if is_macos() {
            Command::new("mount_smbfs")
                .args([&format!("//guest@localhost:{port}/{name}"), &mp])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        } else {
            // Linux: try mount -t cifs (needs root), fall back to gio mount
            let cifs_ok = Command::new("sudo")
                .args([
                    "mount",
                    "-t",
                    "cifs",
                    &format!("//127.0.0.1/{name}"),
                    &mp,
                    "-o",
                    &format!("guest,vers=2.0,port={port}"),
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if cifs_ok {
                true
            } else {
                Command::new("gio")
                    .args(["mount", &format!("smb://guest@localhost:{port}/{name}")])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            }
        };

        if ok {
            eprintln!("Mounted at {mp}");
        } else {
            eprintln!(
                "Mount failed. Try manually:\n  {}",
                mount_cmd_hint(port, &name)
            );
        }
    });

    mount_point
}

/// Unmount a path with platform-appropriate escalation.
fn do_unmount(path: &str) {
    // Strategy 1: umount (works on both platforms)
    if Command::new("umount")
        .arg(path)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return;
    }

    if is_macos() {
        // macOS strategy 2: diskutil
        if Command::new("diskutil")
            .args(["unmount", "force", path])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return;
        }
    } else {
        // Linux strategy 2: lazy unmount
        if Command::new("umount")
            .args(["-l", path])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            return;
        }
    }

    eprintln!("Warning: could not unmount {path}");
}

// ── Subcommands ─────────────────────────────────────────────────────

/// An active mounter mount parsed from `mount` output.
struct MountInfo {
    share: String,  // e.g. "myserver"
    port: u16,      // localhost port
    path: String,   // mount point, e.g. /Users/x/mnt/myserver
    source: String, // full source, e.g. //guest:@localhost:44445/myserver
}

/// Parse `mount` output to find our SMB mounts (guest@localhost).
fn find_smb_mounts() -> Vec<MountInfo> {
    let output = match Command::new("mount").output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return vec![],
    };
    let mut mounts = Vec::new();
    for line in output.lines() {
        // macOS: //guest:@localhost:44445/name on /Users/x/mnt/name (smbfs, ...)
        // Linux: //localhost/name on /home/x/mnt/name type cifs (...)
        if !line.contains("localhost") {
            continue;
        }
        if !line.contains("smbfs") && !line.contains("cifs") {
            continue;
        }
        let parts: Vec<&str> = line.splitn(4, ' ').collect();
        if parts.len() < 4 || parts[1] != "on" {
            continue;
        }
        let source = parts[0];
        let path = parts[2];
        // Parse source: //guest:@localhost:PORT/SHARE
        if let Some(rest) = source.strip_prefix("//") {
            // rest = "guest:@localhost:44445/myserver"
            if let Some(host_start) = rest.find("localhost:") {
                let after_host = &rest[host_start + "localhost:".len()..];
                // after_host = "44445/myserver"
                if let Some(slash) = after_host.find('/') {
                    let port: u16 = after_host[..slash].parse().unwrap_or(0);
                    let share = &after_host[slash + 1..];
                    if port > 0 {
                        mounts.push(MountInfo {
                            share: share.to_string(),
                            port,
                            path: path.to_string(),
                            source: source.to_string(),
                        });
                    }
                }
            }
        }
    }
    mounts
}

/// Kill the mounter process listening on the given port.
fn kill_server(port: u16) -> bool {
    let output = match Command::new("lsof")
        .args(["-ti", &format!(":{port}")])
        .output()
    {
        Ok(o) => o,
        Err(_) => return false,
    };
    let pids = String::from_utf8_lossy(&output.stdout);
    let mut killed = false;
    for pid_str in pids.split_whitespace() {
        if let Ok(pid) = pid_str.parse::<u32>() {
            // Verify it's actually mounter before killing
            if let Ok(ps) = Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "comm="])
                .output()
            {
                let comm = String::from_utf8_lossy(&ps.stdout);
                if comm.trim().contains("mounter") {
                    let _ = Command::new("kill").arg(pid.to_string()).status();
                    eprintln!("  killed server pid {pid}");
                    killed = true;
                }
            }
        }
    }
    killed
}

/// Unmount a single mount with escalating force.
fn unmount_one(info: &MountInfo) -> bool {
    eprintln!("Unmounting {} ({})", info.share, info.path);

    // Strategy 1: normal umount
    if Command::new("umount")
        .arg(&info.path)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        eprintln!("  unmounted");
        kill_server(info.port);
        return true;
    }

    // Strategy 2: platform-specific
    if is_macos() {
        if Command::new("diskutil")
            .args(["unmount", &info.path])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            eprintln!("  unmounted (diskutil)");
            kill_server(info.port);
            return true;
        }
    }

    // Strategy 3: kill the server first, then force unmount.
    // Killing the server drops the TCP connection, which makes the OS
    // release the mount more willingly.
    eprintln!("  mount busy — killing server and force-unmounting");
    kill_server(info.port);
    std::thread::sleep(std::time::Duration::from_millis(500));

    let force_ok = if is_macos() {
        Command::new("diskutil")
            .args(["unmount", "force", &info.path])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    } else {
        // Linux: lazy unmount detaches immediately
        Command::new("umount")
            .args(["-l", &info.path])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };

    if force_ok {
        eprintln!("  force-unmounted");
        return true;
    }

    eprintln!("  failed to unmount {}", info.path);
    false
}

fn cmd_unmount(target: &str) -> i32 {
    let mounts = find_smb_mounts();
    if mounts.is_empty() {
        eprintln!("No active mounter mounts found.");
        return 1;
    }

    if target == "all" {
        let mut failures = 0;
        for m in &mounts {
            if !unmount_one(m) {
                failures += 1;
            }
        }
        return if failures > 0 { 1 } else { 0 };
    }

    // Match by share name or mount path
    let matched: Vec<&MountInfo> = mounts
        .iter()
        .filter(|m| {
            m.share == target || m.path == target || m.path.ends_with(&format!("/{target}"))
        })
        .collect();

    if matched.is_empty() {
        eprintln!("No mount matching '{target}'. Active mounts:");
        for m in &mounts {
            eprintln!("  {} → {}", m.share, m.path);
        }
        return 1;
    }

    let mut failures = 0;
    for m in matched {
        if !unmount_one(m) {
            failures += 1;
        }
    }
    if failures > 0 {
        1
    } else {
        0
    }
}

fn cmd_list() {
    let mounts = find_smb_mounts();
    if mounts.is_empty() {
        println!("No active mounter mounts.");
        return;
    }
    for m in &mounts {
        println!("{:<20} {} (port {})", m.share, m.path, m.port);
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
