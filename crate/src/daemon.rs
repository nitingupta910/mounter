//! Background daemon spawn and log polling.

use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DAEMON_MARKER_ENV: &str = "_MOUNTER_DAEMONIZED";

/// Re-exec self as a detached daemon with output redirected to a log file.
/// Polls the log file for the "Mounted at" message, then exits.
pub fn spawn_daemon(args: &[String]) -> ! {
    use std::time::{Duration, Instant};

    let (log_path, log_file) = match create_daemon_log() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Failed to create log file: {e}");
            process::exit(1);
        }
    };
    let log_err = log_file.try_clone().unwrap();

    let exe = env::current_exe().unwrap_or_else(|_| args[0].clone().into());
    let mut cmd = process::Command::new(exe);
    cmd.args(&args[1..]);
    cmd.env(DAEMON_MARKER_ENV, "1");
    cmd.stdin(process::Stdio::null());
    cmd.stdout(log_file);
    cmd.stderr(log_err);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to start daemon: {e}");
            process::exit(1);
        }
    };

    // Poll log file for mount success or failure
    let start = Instant::now();
    let timeout = Duration::from_secs(30);
    loop {
        // Check if child died prematurely
        if let Ok(Some(status)) = child.try_wait() {
            let mut content = String::new();
            let _ = File::open(&log_path).and_then(|mut f| f.read_to_string(&mut content));
            eprint!("{content}");
            eprintln!("mounter daemon exited early: {status}");
            process::exit(1);
        }

        let content = std::fs::read_to_string(&log_path).unwrap_or_default();
        if content.contains("Mounted at") {
            // Relay log output up to this point, then detach
            print!("{content}");
            println!("(mounter running in background — unmount with `mounter unmount`)");
            let _ = std::fs::remove_file(&log_path);
            process::exit(0);
        }
        if content.contains("Mount failed") || content.contains("SSH connection failed") {
            eprint!("{content}");
            let _ = child.kill();
            process::exit(1);
        }
        if start.elapsed() > timeout {
            eprintln!("Timeout waiting for mount. Log: {}", log_path.display());
            let _ = child.kill();
            process::exit(1);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub(crate) fn create_daemon_log() -> io::Result<(PathBuf, File)> {
    let dir = env::temp_dir().join("mounter");
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }

    for _ in 0..16 {
        let path = dir.join(format!(
            "mounter-{}-{}.log",
            std::process::id(),
            random_hex_64()
        ));
        match create_exclusive_log_file(&path) {
            Ok(file) => return Ok((path, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create unique daemon log",
    ))
}

fn create_exclusive_log_file(path: &std::path::Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn random_hex_64() -> String {
    let mut bytes = [0u8; 8];
    let filled = File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .is_ok();
    if !filled {
        bytes = (SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            ^ std::process::id() as u128)
            .to_le_bytes()[..8]
            .try_into()
            .unwrap_or([0; 8]);
    }
    let mut out = String::with_capacity(16);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_log_is_created_under_process_temp_dir() {
        let (path, _file) = create_daemon_log().unwrap();
        assert!(path.starts_with(env::temp_dir().join("mounter")));
        assert!(!path.starts_with("/tmp/mounter-"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn exclusive_log_creation_does_not_overwrite_existing_file() {
        let path = env::temp_dir().join(format!("mounter-existing-test-{}", std::process::id()));
        std::fs::write(&path, b"keep").unwrap();
        let err = create_exclusive_log_file(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn exclusive_log_creation_rejects_symlink_path() {
        use std::os::unix::fs::symlink;

        let target = env::temp_dir().join(format!("mounter-symlink-target-{}", std::process::id()));
        let link = env::temp_dir().join(format!("mounter-symlink-link-{}", std::process::id()));
        std::fs::write(&target, b"target").unwrap();
        let _ = std::fs::remove_file(&link);
        symlink(&target, &link).unwrap();

        let err = create_exclusive_log_file(&link).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&target).unwrap(), b"target");

        let _ = std::fs::remove_file(link);
        let _ = std::fs::remove_file(target);
    }
}
