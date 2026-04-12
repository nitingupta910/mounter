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

`sshfs-rs` is our Rust reimplementation of sshfs (1,200 lines vs 5,170 in the unmaintained C original). It speaks SFTP v3 over an `ssh` subprocess — your existing keys, config, and agent just work.

A background monitor process auto-recovers stale mounts after sleep/wake or network changes.

## Project structure

| Directory | What | Target |
|---|---|---|
| `mounter/` | macOS CLI + monitor daemon | macOS (native) |
| `sshfs-rs/` | SFTP/FUSE filesystem | Linux (Docker) |
| `mounter` | Bash fallback (no Rust needed) | macOS |

## License

Apache 2.0
