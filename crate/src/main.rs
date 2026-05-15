//! mounter: Mount remote SSH directories via SMB2-over-SFTP.
//!
//! Single binary — SMB2 server + SFTP client in one process.
//! Works on macOS (`mount_smbfs`) and Linux (`gio mount`).
//! No Docker, no FUSE, no kernel extensions, no sudo.

mod cli;
mod client;
mod daemon;
mod server;
mod sftp;
mod smb2;

use cli::{cmd_list, cmd_unmount, generate_smb_user, mount_cmd_hint, parse_remote, spawn_mount};
use client::handle_client;
use daemon::{DAEMON_MARKER_ENV, spawn_daemon};
use sftp::ReconnectingSftp;
use std::env;
use std::net::TcpListener;
use std::process;
use std::sync::Arc;
use std::thread;
fn usage() -> ! {
    eprintln!("mounter — mount remote SSH directories via SMB2-over-SFTP");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  mounter mount [user@]host:[path] <mountpoint> [opts]  Mount and serve");
    eprintln!("  mounter [user@]host:[path] [opts]                     Start SMB server only");
    eprintln!("  mounter unmount <name|path|all>                        Unmount cleanly");
    eprintln!("  mounter list                                           Show active mounts");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -p PORT         SSH port (default: 22)");
    eprintln!("  -i IDENTITY     SSH identity file");
    eprintln!("  -n NAME         Share name (default: host)");
    eprintln!("  --smb-port PORT Local SMB port (default: auto)");
    eprintln!("  --accept-new-host-key  Allow SSH to trust a new host key on first use");
    eprintln!("  -f, --foreground  Run in foreground (default: daemonize after mount)");
    process::exit(1);
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let raw_args: Vec<String> = env::args().collect();
    if raw_args.len() < 2 {
        usage();
    }

    // Extract -f/--foreground flag out of args so subsequent parsing is unaffected
    let foreground = raw_args.iter().any(|a| a == "-f" || a == "--foreground");
    let args: Vec<String> = raw_args
        .iter()
        .filter(|a| a.as_str() != "-f" && a.as_str() != "--foreground")
        .cloned()
        .collect();
    let is_daemon_child = env::var(DAEMON_MARKER_ENV).is_ok();

    // Daemonize the "mount" subcommand by default unless -f is given
    if args.len() >= 2 && args[1] == "mount" && !foreground && !is_daemon_child {
        spawn_daemon(&raw_args);
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

    // For "mount" subcommand: mounter mount user@host:path /mount/point [opts]
    let remote_idx = if auto_mount { 2 } else { 1 };
    let remote = match args.get(remote_idx) {
        Some(r) => r,
        None => {
            if auto_mount {
                eprintln!("Usage: mounter mount [user@]host:[path] <mountpoint> [opts]");
            } else {
                eprintln!("Usage: mounter [user@]host:[path] [opts]");
            }
            process::exit(1);
        }
    };

    // Mount subcommand requires a mount point as the next positional arg
    let mount_point = if auto_mount {
        match args.get(remote_idx + 1) {
            Some(mp) if !mp.starts_with('-') => Some(mp.clone()),
            _ => {
                eprintln!(
                    "Missing mount point. Usage: mounter mount [user@]host:[path] <mountpoint>"
                );
                process::exit(1);
            }
        }
    } else {
        None
    };
    let opt_start = if auto_mount {
        remote_idx + 2
    } else {
        remote_idx + 1
    };
    let mut ssh_port: u16 = 22;
    let mut identity: Option<String> = None;
    let mut share_name: Option<String> = None;
    let mut smb_port: u16 = 0; // 0 = auto-assign
    let mut accept_new_host_key = false;

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
            "--accept-new-host-key" => {
                accept_new_host_key = true;
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
    let smb_user = generate_smb_user();

    // Connect via SFTP
    log::info!("Connecting to {host}:{ssh_port}...");
    let sftp = match ReconnectingSftp::connect(
        &host,
        ssh_port,
        user.as_deref(),
        identity.as_deref(),
        accept_new_host_key,
    ) {
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

    if let Some(ref mp) = mount_point {
        spawn_mount(local_port, &name, mp, &smb_user);
        println!("Press Ctrl-C to stop. Clean up with: mounter unmount {name}");
    } else {
        println!("Mount with:");
        println!("  {}", mount_cmd_hint(local_port, &name, &smb_user));
    }

    // Accept connections — one thread per client
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let sftp = Arc::clone(&sftp);
                let root = root.clone();
                let name = name.clone();
                let smb_user = smb_user.clone();
                thread::spawn(move || handle_client(stream, sftp, root, name, smb_user));
            }
            Err(e) => log::warn!("Accept error: {e}"),
        }
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
