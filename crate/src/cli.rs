//! Mount/unmount CLI helpers.

use std::io::Read;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn is_macos() -> bool {
    cfg!(target_os = "macos")
}

pub(crate) fn generate_smb_user() -> String {
    let mut bytes = [0u8; 16];
    let filled = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .is_ok();
    if !filled {
        let fallback = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            ^ std::process::id() as u128;
        bytes = fallback.to_le_bytes();
    }

    let mut token = String::with_capacity(40);
    token.push_str("mounter-");
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(token, "{b:02x}");
    }
    token
}

pub(crate) fn mount_cmd_hint(port: u16, name: &str, smb_user: &str) -> String {
    if is_macos() {
        format!("mount_smbfs //{smb_user}:@localhost:{port}/{name} <mountpoint>")
    } else {
        format!("gio mount smb://{smb_user}@127.0.0.1:{port}/{name}")
    }
}

/// Spawn the mount command in the background (non-blocking).
/// The mount will complete once the SMB server starts accepting connections.
pub fn spawn_mount(port: u16, name: &str, mount_point: &str, smb_user: &str) {
    let _ = std::fs::create_dir_all(mount_point);

    let mp = mount_point.to_string();
    let name = name.to_string();
    let smb_user = smb_user.to_string();
    std::thread::spawn(move || {
        let ok = if is_macos() {
            Command::new("mount_smbfs")
                .args([&format!("//{smb_user}:@localhost:{port}/{name}"), &mp])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        } else {
            // Linux: gio mount (userspace SMB, no root needed)
            Command::new("gio")
                .args([
                    "mount",
                    &format!("smb://{smb_user}@127.0.0.1:{port}/{name}"),
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        };

        if ok {
            eprintln!("Mounted at {mp}");
        } else {
            eprintln!(
                "Mount failed. Try manually:\n  {}",
                mount_cmd_hint(port, &name, &smb_user)
            );
        }
    });
}

// ── Subcommands ─────────────────────────────────────────────────────

/// An active mounter mount parsed from `mount` output.
struct MountInfo {
    share: String, // e.g. "myserver"
    port: u16,     // localhost port
    path: String,  // mount point, e.g. /Users/x/mnt/myserver
}

/// Parse `mount` output to find our SMB mounts.
/// Supports both old format (guest@localhost:PORT/SHARE) and
/// new format (guest@SHARE:PORT/SHARE).
fn find_smb_mounts() -> Vec<MountInfo> {
    let output = match Command::new("mount").output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return vec![],
    };
    let mut mounts = Vec::new();
    for line in output.lines() {
        if !line.contains("smbfs") && !line.contains("smb") {
            continue;
        }
        let parts: Vec<&str> = line.splitn(4, ' ').collect();
        if parts.len() < 4 || parts[1] != "on" {
            continue;
        }
        let source = parts[0];
        let path = parts[2];
        // Parse source: //guest:@HOST:PORT/SHARE
        // where HOST is either "localhost" (old) or the share name (new)
        if let Some(rest) = source.strip_prefix("//") {
            // rest = "guest:@HOST:PORT/SHARE"
            if let Some(at) = rest.find('@') {
                let after_at = &rest[at + 1..];
                // after_at = "HOST:PORT/SHARE"
                if let Some(colon) = after_at.find(':') {
                    let host = &after_at[..colon];
                    let after_colon = &after_at[colon + 1..];
                    if let Some(slash) = after_colon.find('/') {
                        let port: u16 = after_colon[..slash].parse().unwrap_or(0);
                        let share = &after_colon[slash + 1..];
                        // Accept: host is "localhost", "SHARE.localhost", or "SHARE"
                        let is_ours = host == "localhost"
                            || host == share
                            || host.strip_suffix(".localhost").is_some_and(|h| h == share);
                        if port > 0 && is_ours {
                            mounts.push(MountInfo {
                                share: share.to_string(),
                                port,
                                path: path.to_string(),
                            });
                        }
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

pub fn cmd_unmount(target: &str) -> i32 {
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
    if failures > 0 { 1 } else { 0 }
}

pub fn cmd_list() {
    let mounts = find_smb_mounts();
    if mounts.is_empty() {
        println!("No active mounter mounts.");
        return;
    }
    for m in &mounts {
        println!("{:<20} {} (port {})", m.share, m.path, m.port);
    }
}

pub fn parse_remote(spec: &str) -> (Option<String>, String, String) {
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
