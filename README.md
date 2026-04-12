# mounter

Mount remote SSH directories in macOS Finder. No macFUSE, no sudo.

## Quick start

```bash
git clone https://github.com/nitingupta910/mounter.git && cd mounter

# Build the macOS CLI
cd mounter && cargo build --release
cp target/release/mounter /usr/local/bin/

# Mount (Docker image builds automatically on first run, ~2 min)
mounter mount server:/home/user
mounter mount user@server:/data -n mydata

# Browse files at ~/mnt/<name> or open in Finder
open ~/mnt/server

# Other commands
mounter list
mounter status
mounter unmount server
```

## Requirements

- macOS with [OrbStack](https://orbstack.dev) (provides Docker)
- SSH key auth to your remote server

## How it works

```
Finder ←[SMB]→ Docker container ←[sshfs-rs]→ remote server
```

`sshfs-rs` is a Rust reimplementation of sshfs (~1,800 lines replacing 5,170 lines of unmaintained C). It speaks SFTP v3 over an `ssh` subprocess — existing keys, config, and agent just work.

A background monitor auto-recovers mounts after sleep/wake or network changes using a layered health-check state machine with consecutive-failure gating to tolerate brief network blips.

## Project structure

| Path | What | Target |
|---|---|---|
| `mounter/` | Rust CLI + background health monitor | macOS (native) |
| `sshfs-rs/` | Rust SFTP/FUSE filesystem | Linux (Docker) |
| `mounter.sh` | Bash fallback (no build needed) | macOS |
| `Dockerfile.sshfs-rs` | Multi-stage: builds sshfs-rs + Alpine + samba | Linux |

## License

Apache 2.0
