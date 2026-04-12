mod fs;
mod sftp;

use fuser::MountOption;
use sftp::SftpSession;
use std::sync::Arc;

fn usage() -> ! {
    eprintln!("sshfs-rs — mount remote directories over SSH/SFTP");
    eprintln!();
    eprintln!("Usage: sshfs-rs [user@]host:[path] mountpoint [options]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -p PORT         SSH port (default: 22)");
    eprintln!("  -i IDENTITY     SSH identity file");
    eprintln!("  -o allow_other  Allow other users to access the mount");
    eprintln!("  -f              Run in foreground");
    std::process::exit(1);
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_secs()
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        usage();
    }

    let remote = &args[1];
    let mountpoint = &args[2];
    let mut port: u16 = 22;
    let mut identity: Option<String> = None;
    let mut allow_other = false;
    let mut foreground = false;

    let mut i = 3;
    while i < args.len() {
        match args[i].as_str() {
            "-p" => {
                i += 1;
                port = args
                    .get(i)
                    .expect("missing port value after -p")
                    .parse()
                    .expect("bad port");
            }
            "-i" => {
                i += 1;
                identity = Some(args.get(i).expect("missing path after -i").clone());
            }
            "-f" => {
                foreground = true;
            }
            "-o" => {
                i += 1;
                for opt in args[i].split(',') {
                    match opt.trim() {
                        "allow_other" => allow_other = true,
                        o if o.starts_with("port=") => {
                            port = o[5..].parse().expect("bad port");
                        }
                        o if o.starts_with("IdentityFile=") => {
                            identity = Some(o[13..].to_string());
                        }
                        _ => {
                            log::warn!("ignoring unknown option: {opt}");
                        }
                    }
                }
            }
            _ => {
                eprintln!("unknown arg: {}", args[i]);
                usage();
            }
        }
        i += 1;
    }

    let (user, host, remote_path) = parse_remote(remote);

    log::info!("Connecting to {host}:{port}...");
    let sftp = match SftpSession::connect(&host, port, user.as_deref(), identity.as_deref()) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("Connection failed: {e}");
            std::process::exit(1);
        }
    };

    let root = if remote_path.is_empty() || remote_path == "." {
        sftp.realpath(".").unwrap_or_else(|e| {
            eprintln!("realpath: {e}");
            std::process::exit(1);
        })
    } else {
        sftp.realpath(&remote_path).unwrap_or_else(|e| {
            eprintln!("realpath: {e}");
            std::process::exit(1);
        })
    };

    log::info!("Mounting {root} at {mountpoint}");

    let filesystem = fs::SshFilesystem::new(sftp, &root);

    let mut options = vec![
        MountOption::FSName(format!("sshfs-rs#{host}:{root}")),
        MountOption::DefaultPermissions,
        MountOption::NoDev,
        MountOption::NoSuid,
    ];
    if allow_other {
        options.push(MountOption::AllowOther);
    }

    if foreground {
        fuser::mount2(filesystem, mountpoint, &options).expect("mount failed");
    } else {
        unsafe {
            let pid = libc::fork();
            if pid < 0 {
                eprintln!("fork failed");
                std::process::exit(1);
            }
            if pid > 0 {
                std::process::exit(0);
            } // parent exits
            libc::setsid();
        }
        fuser::mount2(filesystem, mountpoint, &options).expect("mount failed");
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
        (user, rest, ".".to_string())
    }
}

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
        assert_eq!(path, ".");
    }

    #[test]
    fn parse_remote_user_host_only() {
        let (user, host, path) = parse_remote("bob@server");
        assert_eq!(user, Some("bob".to_string()));
        assert_eq!(host, "server");
        assert_eq!(path, ".");
    }

    #[test]
    fn parse_remote_with_subpath() {
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
}
