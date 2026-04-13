# mounter

Mount remote SSH directories in macOS Finder. No macFUSE, no Docker, no sudo.

## Quick start

```bash
cd smb-sshfs
cargo build --release
# Start the SMB-to-SFTP bridge
./target/release/smb-sshfs user@server:/path

# In another terminal, mount it
mkdir -p ~/mnt/server
mount_smbfs //guest@localhost:<port>/server ~/mnt/server
```

The server prints the exact `mount_smbfs` command to run.

## How it works

```
Finder <--SMB2--> smb-sshfs (localhost) <--SFTP/SSH--> remote server
```

`smb-sshfs` is a single Rust binary that speaks SMB2 to macOS and SFTP v3 to
the remote. It spawns `ssh -s sftp` as a subprocess -- existing SSH keys,
config, and agent just work. No kernel extensions, no privileged containers.

## Performance

Benchmarked against raw `ssh cat` on the same connection:

| Operation | Time |
|-----------|------|
| `ls -la` (45 files, cold) | 103 ms |
| `ls -la` (45 files, warm) | 5 ms |
| `stat` single file | 5 ms |
| 108 MB sequential read | 91% of SSH throughput |

Key optimizations:
- **Session-level directory cache** -- macOS sends hundreds of per-file
  QUERY_DIRECTORY lookups for `ls -la`; all served from a 15s TTL cache
  after one SFTP readdir.
- **Pipelined SFTP reads** -- large reads send multiple 256KB requests
  in parallel to saturate the SSH pipe.
- **Read caching** -- each SFTP response is cached so macOS's 2KB
  resource-fork probes don't trigger extra round-trips.
- **Negative caching** -- Apple metadata files (.DS_Store, ._*, etc.)
  that never exist on Linux are cached as absent for 60s.

## Options

```
smb-sshfs [user@]host:[path] [options]

  -p PORT         SSH port (default: 22)
  -i IDENTITY     SSH identity file
  -n NAME         Share name (default: host)
  --smb-port PORT Local SMB port (default: auto)
```

## Requirements

- macOS
- SSH key auth to your remote server
- Rust toolchain (to build)

## Tests and benchmarks

```bash
cargo test          # 54 unit tests
cargo bench         # criterion benchmarks for hot paths
```

## License

Apache 2.0
