# mounter

Mount remote SSH directories in macOS Finder. No macFUSE, no sudo.

## Quick start

```bash
git clone https://github.com/nitingupta910/mounter.git && cd mounter/mounter
cargo build --release
cp target/release/mounter /usr/local/bin/
```

## Usage

```bash
mounter mount server:/home/user
mounter mount user@server:/data -n mydata
mounter list
mounter status
mounter unmount server
```

Files appear at `~/mnt/<name>`. Open in Finder with `open ~/mnt/server`.

## Requirements

- macOS with [OrbStack](https://orbstack.dev)
- SSH key auth to your remote server

## How it works

```
Finder ←[SMB]→ Docker container ←[sshfs-rs]→ remote server
```

`sshfs-rs` is a Rust reimplementation of the unmaintained C sshfs. It speaks SFTP v3 over an `ssh` subprocess — existing keys, config, and agent just work.

A background monitor auto-recovers mounts after sleep/wake or network changes.

## License

Apache 2.0
