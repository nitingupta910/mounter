# mounter

Mount remote SSH directories in your file manager. No FUSE, no Docker, no kernel extensions.

Works on macOS and Linux.

## Install

```bash
cargo install mounter
```

## Quick start

```bash
mounter mount user@server:/path ~/mnt/server
```

That's it. Press Ctrl-C to stop.

## Commands

```
mounter mount [user@]host:[path] <mountpoint> [opts]   Mount and serve
mounter unmount <name|path|all>            Unmount cleanly (handles busy mounts)
mounter list                               Show active mounts
```

Options:

```
  -p PORT         SSH port (default: 22)
  -i IDENTITY     SSH identity file
  -n NAME         Share name (default: host)
  --smb-port PORT Local SMB port (default: auto)
```

## How it works

```
File manager <--SMB2--> mounter (localhost) <--SFTP/SSH--> remote server
```

A single Rust binary that speaks SMB2 to your OS and SFTP v3 to the remote.
It spawns `ssh -s sftp` as a subprocess — existing SSH keys, config, and
agent just work. No kernel extensions, no privileged containers.

## Performance

Benchmarked against raw `ssh cat` on the same connection:

| Operation | Time |
|-----------|------|
| `ls -la` (45 files, cold) | 103 ms |
| `ls -la` (45 files, warm) | 5 ms |
| `stat` single file | 5 ms |
| 108 MB sequential read | 91% of SSH throughput |

Key optimizations:
- **Session-level directory cache** — macOS sends hundreds of per-file
  QUERY_DIRECTORY lookups for `ls -la`; all served from a 15s TTL cache
  after one SFTP readdir.
- **Pipelined SFTP reads** — large reads send multiple 256KB requests
  in parallel to saturate the SSH pipe.
- **Read caching** — each SFTP response is cached so small
  resource-fork probes don't trigger extra round-trips.
- **Negative caching** — Apple metadata files (.DS_Store, ._*, etc.)
  that never exist on Linux are cached as absent for 60s.

## Requirements

- macOS or Linux
- SSH key auth to your remote server

## Development

```bash
cd crate
cargo test          # 54 unit tests
cargo bench         # criterion benchmarks for hot paths
```

## License

Apache 2.0
