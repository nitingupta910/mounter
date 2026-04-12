# mounter

Mount remote Linux directories over SSH so they appear in Finder. No macFUSE, no kernel extensions, no sudo.

## How it works

```
macOS Finder ←[SMB]→ Docker container ←[sshfs]→ remote server
```

A lightweight Docker container (via [OrbStack](https://orbstack.dev)) runs the latest [sshfs](https://github.com/libfuse/sshfs) built from source. Remote files are exported to macOS over SMB using Samba. macOS mounts the SMB share as a regular user — no sudo required.

## Requirements

- macOS 14+
- [OrbStack](https://orbstack.dev) (provides Docker + lightweight Linux VM)
- SSH key-based auth to your remote server

## Install

```bash
# Build the CLI
swift build -c release

# Optional: add to PATH
cp .build/release/mounter /usr/local/bin/
```

The Docker image (sshfs from source + Samba) is built automatically on first mount (~2 min, then cached).

## Usage

```bash
# Mount a remote directory (appears at ~/mnt/<host>)
mounter mount user@server:/home/user

# Mount with a custom name
mounter mount server:/data --name mydata

# List active mounts
mounter list

# Check status
mounter status

# Unmount
mounter unmount server
```

Mounts are accessible in Finder at `~/mnt/<name>` and support read/write.

## How resilience works

| Scenario | Handling |
|---|---|
| Poor connection | sshfs `reconnect` + `ServerAliveInterval` retries automatically |
| Sleep/wake | macOS SMB client reconnects to container; sshfs reconnects to remote |
| Container restart | `--restart unless-stopped` policy; re-run `mounter mount` to restore SMB |

## Architecture

- **sshfs 3.7.5** built from source in a multi-stage Docker build
- **Samba** exports sshfs mounts as SMB shares inside the container
- **`mount_smbfs`** on macOS mounts the share without sudo
- Hostnames are resolved on macOS before passing to the container (handles Tailscale, custom DNS, `/etc/hosts`)
- SSH config (`~/.ssh/config`) is respected for host resolution, user, port, and identity files

## License

Apache License 2.0
