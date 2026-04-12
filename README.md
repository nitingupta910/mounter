# mounter

Mount remote Linux directories over SSH so they appear in Finder. No macFUSE, no kernel extensions, no sudo.

## How it works

```
macOS Finder ←[SMB]→ Docker container ←[sshfs]→ remote server
```

A lightweight Docker container (via [OrbStack](https://orbstack.dev)) runs [sshfs 3.7.5](https://github.com/libfuse/sshfs) built from source. Remote files are exported to macOS over SMB. The macOS SMB client mounts them as a regular user — no sudo needed.

## Requirements

- macOS with [OrbStack](https://orbstack.dev) (provides Docker)
- SSH key-based auth to your remote server

## Install

```bash
# Clone and add to PATH
git clone https://github.com/nitingupta910/mounter.git
ln -s "$(pwd)/mounter/mounter" /usr/local/bin/mounter
```

The Docker image (~79 MB, Alpine-based) is built automatically on first mount.

## Usage

```bash
mounter mount server:/home/user           # mount at ~/mnt/server
mounter mount user@server:/data -n mydata # custom name → ~/mnt/mydata
mounter list                              # show active mounts
mounter status                            # container + sshfs info
mounter unmount server                    # clean teardown
```

Respects `~/.ssh/config` for hostname, user, port, and identity file resolution.

## Resilience

| Scenario | Handling |
|---|---|
| Brief disconnect | sshfs `-o reconnect` + `ServerAliveInterval` retries automatically |
| Long disconnect / sleep | In-container health monitor detects stale mounts and remounts every 30s |
| Container restart | `--restart unless-stopped` policy; saved mount configs enable auto-remount |
| macOS SMB reconnect | macOS kernel SMB client reconnects automatically once sshfs is back |

## Architecture

- **Dockerfile**: multi-stage build — sshfs 3.7.5 from git source, Alpine 3.21 runtime (~79 MB)
- **`mounter`**: bash CLI that orchestrates `docker`, `ssh -G`, `mount_smbfs`
- **`monitor.sh`**: runs inside the container, health-checks mounts every 30s, auto-remounts stale FUSE mounts
- **`entrypoint.sh`**: starts Samba + health monitor
- Hostnames resolved on macOS before passing to the container (handles Tailscale, custom DNS)

## License

Apache License 2.0
