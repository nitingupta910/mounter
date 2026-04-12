//! mounter-rs — macOS CLI for mounting remote SSH directories via Docker + SMB.
//!
//! Ports the `mounter` bash script to Rust with a background health-monitor process.
//! No external crate dependencies; shells out to docker, ssh, mount_smbfs, etc.

use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::thread;
use std::time::Duration;

const IMAGE: &str = "mounter-sshfs-rs";
const CONTAINER: &str = "mounter";

// ── Helpers ─────────────────────────────────────────────────────────

fn mount_base() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join("mnt")
}

fn config_dir() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".config").join("mounter")
}

fn pid_dir() -> PathBuf {
    config_dir().join("pids")
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    process::exit(1);
}

fn info(msg: &str) {
    eprintln!(":: {msg}");
}

/// Run a command, capture stdout+stderr combined, return (success, output).
fn shell(args: &[&str]) -> (bool, String) {
    if args.is_empty() {
        return (false, String::new());
    }
    let result = Command::new(args[0])
        .args(&args[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    match result {
        Ok(out) => {
            let mut s = String::from_utf8_lossy(&out.stdout).to_string();
            s.push_str(&String::from_utf8_lossy(&out.stderr));
            (out.status.success(), s)
        }
        Err(e) => (false, format!("exec error: {e}")),
    }
}

/// Run a command with a timeout. Returns (success, output).
/// On timeout, kills the process and returns (false, "timeout").
fn shell_timeout(args: &[&str], timeout_secs: u64) -> (bool, String) {
    if args.is_empty() {
        return (false, String::new());
    }
    let mut child = match Command::new(args[0])
        .args(&args[1..])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => return (false, format!("exec error: {e}")),
    };

    let timeout = Duration::from_secs(timeout_secs);
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut s = String::new();
                if let Some(mut stdout) = child.stdout.take() {
                    io::Read::read_to_string(&mut stdout, &mut s).ok();
                }
                if let Some(mut stderr) = child.stderr.take() {
                    let mut es = String::new();
                    io::Read::read_to_string(&mut stderr, &mut es).ok();
                    s.push_str(&es);
                }
                return (status.success(), s);
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return (false, "timeout".into());
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return (false, format!("wait error: {e}")),
        }
    }
}

/// Execute a command inside the mounter container.
fn docker_exec(cmd: &str) -> (bool, String) {
    shell(&["docker", "exec", CONTAINER, "sh", "-c", cmd])
}

/// Get the container's IP address.
fn docker_container_ip() -> String {
    let (ok, out) = shell(&[
        "docker",
        "inspect",
        "-f",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        CONTAINER,
    ]);
    if ok {
        out.trim().to_string()
    } else {
        String::new()
    }
}

/// Check if the container is running.
fn container_running() -> bool {
    let (ok, out) = shell(&["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER]);
    ok && out.trim() == "true"
}

/// Ensure the Docker image exists, build if needed.
fn ensure_image() {
    let (ok, _) = shell(&["docker", "image", "inspect", IMAGE]);
    if ok {
        return;
    }
    info("Building sshfs image (one-time)...");
    // Find the project directory (where Dockerfile lives)
    let exe = env::current_exe().unwrap_or_default();
    let project_dir = exe
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .unwrap_or_else(|| Path::new("."));
    // Try several locations for the Dockerfile
    let candidates = [
        project_dir.to_path_buf(),
        PathBuf::from(env::var("MOUNTER_DIR").unwrap_or_default()),
        PathBuf::from("."),
    ];
    for dir in &candidates {
        if dir.join("Dockerfile").exists() {
            let (ok, out) = shell(&["docker", "build", "-t", IMAGE, &dir.to_string_lossy()]);
            if ok {
                info("Image built.");
                return;
            }
            die(&format!("Docker build failed: {out}"));
        }
    }
    die("Cannot find Dockerfile. Set MOUNTER_DIR or run from the project directory.");
}

/// Ensure the container is running.
fn docker_ensure_running() {
    if container_running() {
        return;
    }
    ensure_image();
    // Check if container exists but is stopped
    let (exists, _) = shell(&["docker", "inspect", CONTAINER]);
    if exists {
        let (ok, out) = shell(&["docker", "start", CONTAINER]);
        if !ok {
            die(&format!("Container start failed: {out}"));
        }
    } else {
        let (ok, out) = shell(&[
            "docker",
            "run",
            "-d",
            "--name",
            CONTAINER,
            "--privileged",
            "--restart",
            "unless-stopped",
            IMAGE,
        ]);
        if !ok {
            die(&format!("Container create failed: {out}"));
        }
    }
    // Wait for smbd
    for _ in 0..10 {
        let (ok, _) = docker_exec("pidof smbd");
        if ok {
            return;
        }
        thread::sleep(Duration::from_millis(500));
    }
}

// ── SSH config resolution ───────────────────────────────────────────

struct SshConfig {
    hostname: String,
    user: String,
    port: String,
    identity_file: String,
}

/// Resolve SSH configuration for a host via `ssh -G`.
fn resolve_ssh(host: &str) -> SshConfig {
    let (ok, out) = shell(&["ssh", "-G", host]);
    let mut cfg = SshConfig {
        hostname: host.to_string(),
        user: String::new(),
        port: "22".to_string(),
        identity_file: String::new(),
    };
    if !ok {
        return cfg;
    }
    let home = env::var("HOME").unwrap_or_default();
    for line in out.lines() {
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() != 2 {
            continue;
        }
        match parts[0] {
            "hostname" => cfg.hostname = parts[1].to_string(),
            "user" => cfg.user = parts[1].to_string(),
            "port" => cfg.port = parts[1].to_string(),
            "identityfile" => {
                if cfg.identity_file.is_empty() {
                    let f = parts[1].replace('~', &home);
                    if Path::new(&f).exists() {
                        cfg.identity_file = f;
                    }
                }
            }
            _ => {}
        }
    }
    cfg
}

/// Resolve a hostname to an IP address using the `host` command.
/// Falls back to the original hostname if resolution fails.
fn resolve_host(hostname: &str) -> String {
    let (ok, out) = shell(&["host", hostname]);
    if !ok {
        return hostname.to_string();
    }
    for line in out.lines() {
        if line.contains("has address") {
            if let Some(ip) = line.split_whitespace().last() {
                return ip.to_string();
            }
        }
    }
    hostname.to_string()
}

// ── Remote spec parsing ─────────────────────────────────────────────

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

// ── PID file management ────────────────────────────────────────────

fn write_pid_file(name: &str, pid: u32) {
    let dir = pid_dir();
    fs::create_dir_all(&dir).ok();
    let path = dir.join(format!("{name}.pid"));
    fs::write(path, pid.to_string()).ok();
}

fn read_pid_file(name: &str) -> Option<u32> {
    let path = pid_dir().join(format!("{name}.pid"));
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn remove_pid_file(name: &str) {
    let path = pid_dir().join(format!("{name}.pid"));
    fs::remove_file(path).ok();
}

// ── Health check ────────────────────────────────────────────────────

fn smb_mount_healthy(name: &str) -> bool {
    let macmount = mount_base().join(name);
    let path_str = macmount.to_string_lossy().to_string();
    let (ok, out) = shell_timeout(&["stat", &path_str], 5);
    if !ok {
        // Also check: timeout means stale mount
        if out == "timeout" {
            return false;
        }
        // Check if it is still in the mount table
        let (_, mounts) = shell(&["mount"]);
        return mounts.contains(&format!(" on {path_str} "));
    }
    true
}

fn sshfs_mounted_in_container(name: &str) -> bool {
    let check = format!("mountpoint -q /mnt/{name} 2>/dev/null");
    let (ok, _) = docker_exec(&check);
    ok
}

fn remount_sshfs(name: &str, user: &str, target_ip: &str, path: &str, port: &str) {
    let vmount = format!("/mnt/{name}");
    let ckey = format!("/root/.ssh/key-{name}");
    let sshfs_cmd = format!(
        "sshfs-rs {user}@{target_ip}:{path} {vmount} -f -o allow_other,IdentityFile={ckey},port={port}"
    );
    // Run in background inside container (nohup + &)
    let cmd = format!("mkdir -p {vmount} && nohup {sshfs_cmd} &");
    docker_exec(&cmd);
}

fn remount_smb(name: &str, container_ip: &str) {
    let macmount = mount_base().join(name);
    let path_str = macmount.to_string_lossy().to_string();
    // Try to unmount first
    shell(&["/sbin/umount", &path_str]);
    thread::sleep(Duration::from_secs(1));
    let smb_url = format!("//guest@{container_ip}/{name}");
    shell(&["/sbin/mount_smbfs", &smb_url, &path_str]);
}

// ── Monitor loop ────────────────────────────────────────────────────

fn monitor_loop(
    name: &str,
    container_ip: &str,
    user: &str,
    target_ip: &str,
    path: &str,
    port: &str,
) {
    // Install signal handler for SIGTERM: clean unmount + exit
    unsafe {
        libc::signal(
            libc::SIGTERM,
            sigterm_handler as *const () as libc::sighandler_t,
        );
    }
    // Store name in a static for signal handler
    MONITOR_NAME.lock().unwrap().replace(name.to_string());

    loop {
        thread::sleep(Duration::from_secs(30));

        if !smb_mount_healthy(name) {
            info(&format!(
                "[monitor] {name}: SMB mount unhealthy, recovering..."
            ));

            if !container_running() {
                info(&format!("[monitor] {name}: restarting container"));
                docker_ensure_running();
            }

            if !sshfs_mounted_in_container(name) {
                info(&format!("[monitor] {name}: remounting sshfs"));
                remount_sshfs(name, user, target_ip, path, port);
                // Wait for sshfs to come up
                thread::sleep(Duration::from_secs(3));
            }

            let cip = if container_ip.is_empty() {
                docker_container_ip()
            } else {
                container_ip.to_string()
            };
            info(&format!("[monitor] {name}: remounting SMB"));
            remount_smb(name, &cip);
        }
    }
}

use std::sync::Mutex as StdMutex;
static MONITOR_NAME: StdMutex<Option<String>> = StdMutex::new(None);

extern "C" fn sigterm_handler(_sig: libc::c_int) {
    // Best-effort cleanup
    if let Ok(guard) = MONITOR_NAME.lock() {
        if let Some(ref name) = *guard {
            let macmount = mount_base().join(name);
            let path_str = macmount.to_string_lossy().to_string();
            // Unmount SMB
            let _ = Command::new("/sbin/umount").arg(&path_str).output();
            // Unmount sshfs in container
            let cmd = format!(
                "fusermount3 -u /mnt/{name} 2>/dev/null || fusermount -u /mnt/{name} 2>/dev/null"
            );
            let _ = Command::new("docker")
                .args(["exec", CONTAINER, "sh", "-c", &cmd])
                .output();
            remove_pid_file(name);
        }
    }
    process::exit(0);
}

// ── Commands ────────────────────────────────────────────────────────

fn cmd_mount(args: &[String]) {
    if args.is_empty() {
        die("Usage: mounter-rs mount [user@]host:[/path] [-p port] [-i identity] [-n name]");
    }

    let remote = &args[0];
    let mut port_override: Option<String> = None;
    let mut identity_override: Option<String> = None;
    let mut name_override: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-p" | "--port" => {
                i += 1;
                port_override = Some(args.get(i).cloned().unwrap_or_default());
            }
            "-i" | "--identity" => {
                i += 1;
                identity_override = Some(args.get(i).cloned().unwrap_or_default());
            }
            "-n" | "--name" => {
                i += 1;
                name_override = Some(args.get(i).cloned().unwrap_or_default());
            }
            other => die(&format!("Unknown option: {other}")),
        }
        i += 1;
    }

    // Parse remote spec
    let (ruser, rhost, rpath) = parse_remote(remote);
    let rpath = if rpath.is_empty() {
        "/".to_string()
    } else {
        rpath
    };

    if rhost.is_empty() {
        die("Empty hostname");
    }

    let name = name_override.unwrap_or_else(|| rhost.clone());

    // Resolve SSH config
    let ssh_cfg = resolve_ssh(&rhost);
    let ssh_user = ruser.unwrap_or(ssh_cfg.user);
    let ssh_port = port_override.unwrap_or(ssh_cfg.port);
    let ssh_key = identity_override.unwrap_or(ssh_cfg.identity_file);

    if ssh_key.is_empty() {
        die("No SSH key found. Use -i/--identity or set up ~/.ssh/id_*");
    }
    if ssh_user.is_empty() {
        die("No SSH user found. Use user@host or configure ~/.ssh/config");
    }

    // Resolve hostname to IP (Tailscale / custom DNS)
    let target_ip = resolve_host(&ssh_cfg.hostname);

    info(&format!(
        "Mounting {}{rhost}:{rpath}",
        if !ssh_user.is_empty() {
            format!("{ssh_user}@")
        } else {
            String::new()
        }
    ));

    // 1. Ensure container is running
    docker_ensure_running();

    // 2. Copy SSH key to container
    let ckey = format!("/root/.ssh/key-{name}");
    let dest = format!("{CONTAINER}:{ckey}");
    let (ok, out) = shell(&["docker", "cp", &ssh_key, &dest]);
    if !ok {
        die(&format!("Failed to copy SSH key: {out}"));
    }
    docker_exec(&format!("chmod 600 {ckey}"));

    // 3. Mount sshfs inside container
    let vmount = format!("/mnt/{name}");
    let (already_mounted, _) = docker_exec(&format!("mountpoint -q {vmount} 2>/dev/null"));
    if already_mounted {
        info("Already mounted in container.");
    } else {
        docker_exec(&format!("mkdir -p {vmount}"));
        let sshfs_cmd = format!(
            "sshfs-rs {ssh_user}@{target_ip}:{rpath} {vmount} -f -o allow_other,IdentityFile={ckey},port={ssh_port}"
        );
        // Run sshfs-rs in background inside container
        let (ok, out) = docker_exec(&format!(
            "nohup {sshfs_cmd} > /var/log/sshfs-{name}.log 2>&1 &"
        ));
        if !ok {
            // Non-fatal: nohup with & may report success strangely
            eprintln!("sshfs launch note: {out}");
        }
        // Give sshfs a moment to connect
        thread::sleep(Duration::from_secs(2));
        let (mounted, _) = docker_exec(&format!("mountpoint -q {vmount} 2>/dev/null"));
        if !mounted {
            // Check log for errors
            let (_, log) = docker_exec(&format!("cat /var/log/sshfs-{name}.log 2>/dev/null"));
            die(&format!("sshfs-rs mount failed. Log: {log}"));
        }
    }

    // 4. Configure samba share
    let (has_share, _) = docker_exec(&format!(
        "grep -q '\\[{name}\\]' /etc/samba/smb.conf 2>/dev/null"
    ));
    if !has_share {
        let samba_conf = format!(
            r#"
[{name}]
path = {vmount}
browseable = yes
read only = no
guest ok = yes
force user = root
create mask = 0644
directory mask = 0755
"#
        );
        // Escape for shell
        let escaped = samba_conf.replace('\'', "'\\''");
        docker_exec(&format!("printf '{escaped}' >> /etc/samba/smb.conf"));
    }
    docker_exec("kill -HUP $(pidof smbd) 2>/dev/null || smbd --daemon --no-process-group");

    // 5. Mount SMB on macOS
    let macmount = mount_base().join(&name);
    fs::create_dir_all(&macmount).ok();
    let mac_path = macmount.to_string_lossy().to_string();

    // Unmount if already mounted
    let (_, mounts) = shell(&["mount"]);
    if mounts.contains(&format!(" on {mac_path} ")) {
        shell(&["/sbin/umount", &mac_path]);
    }

    let cip = docker_container_ip();
    if cip.is_empty() {
        die("Cannot determine container IP");
    }
    let smb_url = format!("//guest@{cip}/{name}");
    let (ok, out) = shell(&["/sbin/mount_smbfs", &smb_url, &mac_path]);
    if !ok {
        die(&format!("SMB mount failed: {out}"));
    }

    info(&format!("Mounted at {mac_path}"));
    println!("Open in Finder:  open {mac_path}");

    // 6. Fork background monitor
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            die("fork failed");
        }
        if pid > 0 {
            // Parent: write child PID and exit
            write_pid_file(&name, pid as u32);
            process::exit(0);
        }
        // Child: become session leader
        libc::setsid();
    }

    // Close stdin (we're a daemon now)
    unsafe {
        libc::close(0);
    }

    // 7. Run monitor loop (never returns)
    monitor_loop(&name, &cip, &ssh_user, &target_ip, &rpath, &ssh_port);
}

fn cmd_unmount(args: &[String]) {
    if args.is_empty() {
        die("Usage: mounter-rs unmount <name>");
    }
    let target = &args[0];
    let name = if target.starts_with('/') {
        Path::new(target)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| target.clone())
    } else {
        target.clone()
    };

    // Kill monitor process
    if let Some(pid) = read_pid_file(&name) {
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
        // Give it a moment to clean up
        thread::sleep(Duration::from_millis(500));
    }

    // Unmount SMB on macOS
    let macmount = mount_base().join(&name);
    let mac_path = macmount.to_string_lossy().to_string();
    let (_, mounts) = shell(&["mount"]);
    if mounts.contains(&format!(" on {mac_path} ")) {
        let (ok, _) = shell(&["/sbin/umount", &mac_path]);
        if !ok {
            shell(&["/usr/sbin/diskutil", "unmount", "force", &mac_path]);
        }
        info(&format!("Unmounted {mac_path}"));
    }

    // Clean up inside container
    if container_running() {
        let cmd = format!(
            "fusermount3 -u /mnt/{name} 2>/dev/null || fusermount -u /mnt/{name} 2>/dev/null"
        );
        docker_exec(&cmd);
        docker_exec(&format!("rm -f /etc/mounter/{name}.conf"));
        // Remove samba share
        docker_exec(&format!(
            "sed -i '/^\\[{name}\\]$/,/^$/d' /etc/samba/smb.conf"
        ));
        docker_exec("kill -HUP $(pidof smbd) 2>/dev/null");
    }

    remove_pid_file(&name);
    println!("Done.");
}

fn cmd_list() {
    if !container_running() {
        println!("No active mounts");
        return;
    }

    let (ok, out) = docker_exec("mount -t fuse.sshfs 2>/dev/null || mount | grep sshfs-rs");
    if !ok || out.trim().is_empty() {
        println!("No active mounts");
        return;
    }

    for line in out.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let remote = parts[0];
        let mount_path = parts[2];
        let name = Path::new(mount_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| mount_path.to_string());
        let mac_path = mount_base().join(&name);
        let mac_str = mac_path.to_string_lossy();

        let (_, mounts) = shell(&["mount"]);
        let status = if mounts.contains(&format!(" on {mac_str} ")) {
            "mounted"
        } else {
            "stale"
        };

        let monitor = match read_pid_file(&name) {
            Some(pid) => {
                // Check if process is alive
                let alive = unsafe { libc::kill(pid as i32, 0) == 0 };
                if alive {
                    format!("monitor pid {pid}")
                } else {
                    "monitor dead".to_string()
                }
            }
            None => "no monitor".to_string(),
        };

        println!("  {name}");
        println!("    Remote:  {remote}");
        println!("    Finder:  {mac_str} [{status}]");
        println!("    Monitor: {monitor}");
        println!();
    }
}

fn cmd_status() {
    if container_running() {
        println!("Container: running");
        let (_, ver) = docker_exec("sshfs-rs --version 2>&1 || echo unknown");
        println!("sshfs-rs:  {}", ver.lines().next().unwrap_or("unknown"));
        let (_, n) = docker_exec("mount -t fuse.sshfs 2>/dev/null | wc -l || echo 0");
        println!("Mounts:    {} active", n.trim());
        let (ok, sz) = shell(&["docker", "image", "inspect", IMAGE, "--format", "{{.Size}}"]);
        if ok {
            if let Ok(bytes) = sz.trim().parse::<u64>() {
                println!("Image:     {} MB", bytes / 1024 / 1024);
            }
        }
        println!("IP:        {}", docker_container_ip());
    } else {
        println!("Container: stopped");
    }
}

fn usage() -> ! {
    eprintln!("mounter-rs — mount remote SSH directories in Finder");
    eprintln!();
    eprintln!("Usage:");
    eprintln!("  mounter-rs mount [user@]host:[/path] [-n name] [-p port] [-i identity]");
    eprintln!("  mounter-rs unmount <name>");
    eprintln!("  mounter-rs list");
    eprintln!("  mounter-rs status");
    eprintln!();
    eprintln!("No macFUSE, no sudo. Requires Docker (OrbStack recommended).");
    process::exit(1);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }

    match args[1].as_str() {
        "mount" => cmd_mount(&args[2..]),
        "unmount" | "umount" => cmd_unmount(&args[2..]),
        "list" | "ls" => cmd_list(),
        "status" => cmd_status(),
        "help" | "-h" | "--help" => usage(),
        other => {
            eprintln!("Unknown command: {other}. Run 'mounter-rs help'");
            process::exit(1);
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_remote_full() {
        let (user, host, path) = parse_remote("alice@myhost:/data");
        assert_eq!(user, Some("alice".to_string()));
        assert_eq!(host, "myhost");
        assert_eq!(path, "/data");
    }

    #[test]
    fn parse_remote_no_user() {
        let (user, host, path) = parse_remote("myhost:/data");
        assert_eq!(user, None);
        assert_eq!(host, "myhost");
        assert_eq!(path, "/data");
    }

    #[test]
    fn parse_remote_no_path() {
        let (user, host, path) = parse_remote("alice@myhost:");
        assert_eq!(user, Some("alice".to_string()));
        assert_eq!(host, "myhost");
        assert_eq!(path, "");
    }

    #[test]
    fn parse_remote_host_only() {
        let (user, host, path) = parse_remote("myhost");
        assert_eq!(user, None);
        assert_eq!(host, "myhost");
        assert_eq!(path, "");
    }

    #[test]
    fn parse_remote_user_host_only() {
        let (user, host, path) = parse_remote("bob@server");
        assert_eq!(user, Some("bob".to_string()));
        assert_eq!(host, "server");
        assert_eq!(path, "");
    }

    #[test]
    fn parse_remote_with_deep_path() {
        let (user, host, path) = parse_remote("user@host:/home/user/projects");
        assert_eq!(user, Some("user".to_string()));
        assert_eq!(host, "host");
        assert_eq!(path, "/home/user/projects");
    }

    #[test]
    fn parse_remote_relative_path() {
        let (user, host, path) = parse_remote("user@host:projects");
        assert_eq!(user, Some("user".to_string()));
        assert_eq!(host, "host");
        assert_eq!(path, "projects");
    }

    #[test]
    fn shell_echo() {
        let (ok, out) = shell(&["echo", "hello"]);
        assert!(ok);
        assert_eq!(out.trim(), "hello");
    }

    #[test]
    fn shell_false() {
        let (ok, _) = shell(&["false"]);
        assert!(!ok);
    }

    #[test]
    fn shell_timeout_fast() {
        let (ok, out) = shell_timeout(&["echo", "fast"], 5);
        assert!(ok);
        assert_eq!(out.trim(), "fast");
    }

    #[test]
    fn shell_timeout_expires() {
        let (ok, out) = shell_timeout(&["sleep", "10"], 1);
        assert!(!ok);
        assert_eq!(out, "timeout");
    }
}
