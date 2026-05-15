//! SFTP session over SSH pipes.

use super::protocol::*;
use super::types::{DirEntry, FileAttr, SftpError, SftpResult};
use super::wire::{Buf, Reader};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

// ── SFTP Session ─────────────────────────────────────────────────────

pub struct SftpSession {
    pub(crate) reader: Mutex<Box<dyn Read + Send>>,
    pub(crate) writer: Mutex<Box<dyn Write + Send>>,
    pub(crate) next_id: AtomicU32,
    pub(crate) _child: Mutex<Option<Child>>,
}

impl SftpSession {
    /// Create a dummy session for unit tests (no real SSH connection).
    #[cfg(test)]
    pub fn dummy() -> Self {
        use std::io::Cursor;
        SftpSession {
            reader: Mutex::new(Box::new(Cursor::new(Vec::<u8>::new()))),
            writer: Mutex::new(Box::new(Cursor::new(Vec::<u8>::new()))),
            next_id: AtomicU32::new(1),
            _child: Mutex::new(None),
        }
    }

    /// Connect to remote host by spawning `ssh -s sftp`.
    pub fn connect(
        host: &str,
        port: u16,
        user: Option<&str>,
        identity: Option<&str>,
        accept_new_host_key: bool,
    ) -> SftpResult<Self> {
        let ssh_args = build_ssh_args(host, port, user, identity, accept_new_host_key)?;
        let (our_sock, child_sock) = UnixStream::pair()?;

        let mut cmd = Command::new("ssh");
        cmd.args(&ssh_args);

        let stdin_fd: OwnedFd = child_sock.try_clone()?.into();
        let stdout_fd: OwnedFd = child_sock.into();
        cmd.stdin(Stdio::from(stdin_fd))
            .stdout(Stdio::from(stdout_fd))
            .stderr(Stdio::inherit());

        let child = cmd.spawn().map_err(|e| {
            SftpError::Io(io::Error::new(
                io::ErrorKind::Other,
                format!("ssh spawn: {e}"),
            ))
        })?;

        let reader = our_sock.try_clone()?;
        let writer = our_sock;

        let session = SftpSession {
            reader: Mutex::new(Box::new(reader)),
            writer: Mutex::new(Box::new(writer)),
            next_id: AtomicU32::new(1),
            _child: Mutex::new(Some(child)),
        };

        session.sftp_init()?;
        Ok(session)
    }

    fn next_id(&self) -> u32 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    // ── Low-level I/O ────────────────────────────────────────────────

    /// Write a packet to an already-locked writer.
    pub(crate) fn write_packet(
        w: &mut dyn Write,
        pkt_type: u8,
        id: u32,
        payload: &[u8],
    ) -> SftpResult<()> {
        let total_len = 1 + 4 + payload.len();
        let mut msg = Vec::with_capacity(4 + total_len);
        msg.extend_from_slice(&(total_len as u32).to_be_bytes());
        msg.push(pkt_type);
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(payload);
        w.write_all(&msg).map_err(|_| SftpError::Disconnected)
    }

    /// Read a packet from an already-locked reader.
    fn read_packet(r: &mut dyn Read) -> SftpResult<(u8, Vec<u8>)> {
        let mut lenbuf = [0u8; 4];
        r.read_exact(&mut lenbuf)
            .map_err(|_| SftpError::Disconnected)?;
        let len = u32::from_be_bytes(lenbuf) as usize;
        if len == 0 || len > 512 * 1024 {
            // Bad length means the stream is irrecoverably out of sync.
            // Treat as Disconnected so the reconnect logic kicks in.
            return Err(SftpError::Disconnected);
        }
        let mut data = vec![0u8; len];
        r.read_exact(&mut data)
            .map_err(|_| SftpError::Disconnected)?;
        Ok((data[0], data[1..].to_vec()))
    }

    fn response_id(data: &[u8]) -> SftpResult<u32> {
        if data.len() < 4 {
            return Err(SftpError::Protocol("response missing request id".into()));
        }
        Ok(u32::from_be_bytes([data[0], data[1], data[2], data[3]]))
    }

    fn drain_packets(r: &mut dyn Read, count: usize) {
        for _ in 0..count {
            let _ = Self::read_packet(r);
        }
    }

    fn send(&self, pkt_type: u8, id: u32, payload: &[u8]) -> SftpResult<()> {
        let mut w = self.writer.lock().map_err(|_| SftpError::Disconnected)?;
        Self::write_packet(&mut *w, pkt_type, id, payload)?;
        w.flush().map_err(|_| SftpError::Disconnected)
    }

    fn send_no_id(&self, pkt_type: u8, payload: &[u8]) -> SftpResult<()> {
        let total_len = 1 + payload.len();
        let mut msg = Vec::with_capacity(4 + total_len);
        msg.extend_from_slice(&(total_len as u32).to_be_bytes());
        msg.push(pkt_type);
        msg.extend_from_slice(payload);

        let mut w = self.writer.lock().map_err(|_| SftpError::Disconnected)?;
        w.write_all(&msg).map_err(|_| SftpError::Disconnected)?;
        w.flush().map_err(|_| SftpError::Disconnected)
    }

    fn recv(&self) -> SftpResult<(u8, Vec<u8>)> {
        let mut r = self.reader.lock().map_err(|_| SftpError::Disconnected)?;
        Self::read_packet(&mut *r)
    }

    /// Send request and receive matching response.
    fn request(&self, pkt_type: u8, payload: &[u8]) -> SftpResult<(u8, Vec<u8>)> {
        let id = self.next_id();
        self.send(pkt_type, id, payload)?;

        // Read response (simple synchronous model — one request at a time per lock)
        let (resp_type, resp_data) = self.recv()?;

        // Verify ID matches (skip for VERSION which has no id)
        if resp_type != SSH_FXP_VERSION {
            let resp_id = Self::response_id(&resp_data)?;
            if resp_id != id {
                return Err(SftpError::Protocol(format!(
                    "id mismatch: sent {id}, got {resp_id}"
                )));
            }
        }

        Ok((resp_type, resp_data))
    }

    fn check_status(&self, resp_type: u8, data: &[u8]) -> SftpResult<()> {
        if resp_type != SSH_FXP_STATUS {
            return Err(SftpError::Protocol(format!(
                "expected STATUS, got {resp_type}"
            )));
        }
        let mut r = Reader::new(&data[4..]); // skip id
        let code = r.get_u32()?;
        if code == SSH_FX_OK {
            return Ok(());
        }
        let msg = r.get_string().unwrap_or_default();
        Err(SftpError::Status(code, msg))
    }

    // ── SFTP init ────────────────────────────────────────────────────

    fn sftp_init(&self) -> SftpResult<()> {
        let mut buf = Buf::new();
        buf.put_u32(SFTP_PROTO_VERSION);
        self.send_no_id(SSH_FXP_INIT, &buf.0)?;

        let (ptype, data) = self.recv()?;
        if ptype != SSH_FXP_VERSION {
            return Err(SftpError::Protocol(format!(
                "expected VERSION, got {ptype}"
            )));
        }
        let version = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        log::info!("SFTP server version: {version}");
        Ok(())
    }

    // ── Public API ───────────────────────────────────────────────────

    pub fn realpath(&self, path: &str) -> SftpResult<String> {
        let mut buf = Buf::new();
        buf.put_str(path);
        let (t, data) = self.request(SSH_FXP_REALPATH, &buf.0)?;
        if t == SSH_FXP_STATUS {
            self.check_status(t, &data)?;
            return Err(SftpError::Protocol("unexpected OK status".into()));
        }
        if t != SSH_FXP_NAME {
            return Err(SftpError::Protocol(format!("expected NAME, got {t}")));
        }
        let mut r = Reader::new(&data[4..]); // skip id
        let count = r.get_u32()?;
        if count == 0 {
            return Err(SftpError::Protocol("empty realpath response".into()));
        }
        r.get_string()
    }

    pub fn stat(&self, path: &str) -> SftpResult<FileAttr> {
        let mut buf = Buf::new();
        buf.put_str(path);
        let (t, data) = self.request(SSH_FXP_STAT, &buf.0)?;
        if t == SSH_FXP_STATUS {
            self.check_status(t, &data)?;
            return Err(SftpError::Protocol("unexpected OK status".into()));
        }
        if t != SSH_FXP_ATTRS {
            return Err(SftpError::Protocol(format!("expected ATTRS, got {t}")));
        }
        Reader::new(&data[4..]).get_attrs()
    }

    pub fn lstat(&self, path: &str) -> SftpResult<FileAttr> {
        let mut buf = Buf::new();
        buf.put_str(path);
        let (t, data) = self.request(SSH_FXP_LSTAT, &buf.0)?;
        if t == SSH_FXP_STATUS {
            self.check_status(t, &data)?;
            return Err(SftpError::Protocol("unexpected OK status".into()));
        }
        if t != SSH_FXP_ATTRS {
            return Err(SftpError::Protocol(format!("expected ATTRS, got {t}")));
        }
        Reader::new(&data[4..]).get_attrs()
    }

    pub fn setstat(&self, path: &str, attrs: &FileAttr) -> SftpResult<()> {
        let mut buf = Buf::new();
        buf.put_str(path);
        buf.put_attrs(attrs);
        let (t, data) = self.request(SSH_FXP_SETSTAT, &buf.0)?;
        self.check_status(t, &data)
    }

    pub fn readdir(&self, path: &str) -> SftpResult<Vec<DirEntry>> {
        // Open directory (1 round-trip)
        let mut buf = Buf::new();
        buf.put_str(path);
        let (t, data) = self.request(SSH_FXP_OPENDIR, &buf.0)?;
        if t == SSH_FXP_STATUS {
            self.check_status(t, &data)?;
            return Err(SftpError::Protocol("unexpected OK status".into()));
        }
        if t != SSH_FXP_HANDLE {
            return Err(SftpError::Protocol(format!("expected HANDLE, got {t}")));
        }
        let handle = Reader::new(&data[4..]).get_bytes()?;

        // READDIR operates on mutable directory-handle state. Even though SFTP
        // responses carry request IDs, the protocol does not guarantee a server
        // will advance a directory stream in request-ID order, so keep READDIR
        // serialized for correctness.
        let result = (|| {
            let mut entries = Vec::new();
            loop {
                let mut rbuf = Buf::new();
                rbuf.put_bytes(&handle);
                let (t, data) = self.request(SSH_FXP_READDIR, &rbuf.0)?;
                if t == SSH_FXP_STATUS {
                    let mut sr = Reader::new(&data[4..]);
                    let code = sr.get_u32()?;
                    if code == SSH_FX_EOF {
                        break;
                    }
                    let msg = sr.get_string().unwrap_or_default();
                    return Err(SftpError::Status(code, msg));
                }
                if t != SSH_FXP_NAME {
                    return Err(SftpError::Disconnected);
                }

                let mut r = Reader::new(&data[4..]);
                let count = r.get_u32()?;
                for _ in 0..count {
                    let name = r.get_string()?;
                    let _longname = r.get_string()?;
                    let attrs = r.get_attrs()?;
                    if name != "." && name != ".." {
                        entries.push(DirEntry { name, attrs });
                    }
                }
            }
            Ok(entries)
        })();

        let _ = self.close_handle(&handle);
        result
    }

    pub fn open(&self, path: &str, flags: u32, mode: u32) -> SftpResult<Vec<u8>> {
        let mut buf = Buf::new();
        buf.put_str(path);
        buf.put_u32(flags);

        // Attrs with permissions
        let mut attr_flags = 0u32;
        if flags & SSH_FXF_CREAT != 0 {
            attr_flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
        }
        buf.put_u32(attr_flags);
        if attr_flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
            buf.put_u32(mode);
        }

        let (t, data) = self.request(SSH_FXP_OPEN, &buf.0)?;
        if t == SSH_FXP_STATUS {
            self.check_status(t, &data)?;
            return Err(SftpError::Protocol("unexpected OK status".into()));
        }
        if t != SSH_FXP_HANDLE {
            return Err(SftpError::Protocol(format!("expected HANDLE, got {t}")));
        }
        Reader::new(&data[4..]).get_bytes()
    }

    fn close_handle(&self, handle: &[u8]) -> SftpResult<()> {
        let mut buf = Buf::new();
        buf.put_bytes(handle);
        let (t, data) = self.request(SSH_FXP_CLOSE, &buf.0)?;
        self.check_status(t, &data)
    }

    pub fn close(&self, handle: &[u8]) -> SftpResult<()> {
        self.close_handle(handle)
    }

    pub fn read(&self, handle: &[u8], offset: u64, len: u32) -> SftpResult<Vec<u8>> {
        struct PendingRead {
            id: u32,
            requested_len: u32,
        }

        let total = len as u64;
        if total <= MAX_READ_SIZE as u64 {
            return self.read_single(handle, offset, len);
        }

        let mut result = Vec::with_capacity(total as usize);
        let mut next_offset = offset;
        let mut remaining = total;
        let mut chunk_size = MAX_READ_SIZE;

        while remaining > 0 {
            let mut pending = Vec::new();
            {
                let mut w = self.writer.lock().map_err(|_| SftpError::Disconnected)?;
                let mut request_offset = next_offset;
                let mut request_remaining = remaining;
                while pending.len() < READ_PIPELINE && request_remaining > 0 {
                    let requested_len = request_remaining.min(chunk_size as u64) as u32;
                    let id = self.next_id();
                    let mut buf = Buf::new();
                    buf.put_bytes(handle);
                    buf.put_u64(request_offset);
                    buf.put_u32(requested_len);
                    Self::write_packet(&mut *w, SSH_FXP_READ, id, &buf.0)?;
                    pending.push(PendingRead { id, requested_len });
                    request_offset += requested_len as u64;
                    request_remaining -= requested_len as u64;
                }
                w.flush().map_err(|_| SftpError::Disconnected)?;
            }

            let mut index_by_id = HashMap::with_capacity(pending.len());
            for request in &pending {
                index_by_id.insert(request.id, request.requested_len);
            }

            let mut responses = HashMap::with_capacity(pending.len());
            {
                let mut r = self.reader.lock().map_err(|_| SftpError::Disconnected)?;
                for received in 0..pending.len() {
                    let (t, data) = Self::read_packet(&mut *r)?;
                    let unread = pending.len() - received - 1;
                    let resp_id = match Self::response_id(&data) {
                        Ok(id) => id,
                        Err(err) => {
                            Self::drain_packets(&mut *r, unread);
                            return Err(err);
                        }
                    };
                    if !index_by_id.contains_key(&resp_id) {
                        Self::drain_packets(&mut *r, unread);
                        return Err(SftpError::Protocol(format!(
                            "pipelined read: unexpected response id {resp_id}"
                        )));
                    }
                    if responses.insert(resp_id, (t, data)).is_some() {
                        Self::drain_packets(&mut *r, unread);
                        return Err(SftpError::Protocol(format!(
                            "pipelined read: duplicate response id {resp_id}"
                        )));
                    }
                }
            }

            let mut restart = false;
            for request in &pending {
                let Some((t, data)) = responses.remove(&request.id) else {
                    return Err(SftpError::Protocol(
                        "pipelined read: missing response".into(),
                    ));
                };

                if t == SSH_FXP_STATUS {
                    let mut sr = Reader::new(&data[4..]);
                    let code = sr.get_u32()?;
                    if code == SSH_FX_EOF {
                        return Ok(result);
                    }
                    let msg = sr.get_string().unwrap_or_default();
                    return Err(SftpError::Status(code, msg));
                }
                if t != SSH_FXP_DATA {
                    return Err(SftpError::Disconnected);
                }

                let chunk = Reader::new(&data[4..]).get_bytes()?;
                if chunk.is_empty() {
                    return Ok(result);
                }

                next_offset += chunk.len() as u64;
                remaining -= chunk.len() as u64;
                result.extend_from_slice(&chunk);

                if chunk.len() < request.requested_len as usize {
                    // Later in-flight requests were scheduled assuming a full
                    // chunk at this offset, so discard those responses and retry
                    // from the first unread byte with a server-proven chunk size.
                    chunk_size = chunk_size.min(chunk.len() as u32);
                    restart = true;
                    break;
                }
                if remaining == 0 {
                    return Ok(result);
                }
            }

            if !restart {
                break;
            }
        }

        Ok(result)
    }

    fn read_single(&self, handle: &[u8], offset: u64, len: u32) -> SftpResult<Vec<u8>> {
        let len = len.min(MAX_READ_SIZE);
        let mut buf = Buf::new();
        buf.put_bytes(handle);
        buf.put_u64(offset);
        buf.put_u32(len);

        let (t, data) = self.request(SSH_FXP_READ, &buf.0)?;
        if t == SSH_FXP_STATUS {
            let mut sr = Reader::new(&data[4..]);
            let code = sr.get_u32()?;
            if code == SSH_FX_EOF {
                return Ok(Vec::new());
            }
            let msg = sr.get_string().unwrap_or_default();
            return Err(SftpError::Status(code, msg));
        }
        if t != SSH_FXP_DATA {
            return Err(SftpError::Protocol(format!("expected DATA, got {t}")));
        }
        Reader::new(&data[4..]).get_bytes()
    }

    pub fn write(&self, handle: &[u8], offset: u64, data: &[u8]) -> SftpResult<()> {
        let mut buf = Buf::with_capacity(data.len() + 32);
        buf.put_bytes(handle);
        buf.put_u64(offset);
        buf.put_bytes(data);

        let (t, resp) = self.request(SSH_FXP_WRITE, &buf.0)?;
        self.check_status(t, &resp)
    }

    pub fn mkdir(&self, path: &str, mode: u32) -> SftpResult<()> {
        let mut buf = Buf::new();
        buf.put_str(path);
        buf.put_u32(SSH_FILEXFER_ATTR_PERMISSIONS);
        buf.put_u32(mode);
        let (t, data) = self.request(SSH_FXP_MKDIR, &buf.0)?;
        self.check_status(t, &data)
    }

    pub fn rmdir(&self, path: &str) -> SftpResult<()> {
        let mut buf = Buf::new();
        buf.put_str(path);
        let (t, data) = self.request(SSH_FXP_RMDIR, &buf.0)?;
        self.check_status(t, &data)
    }

    pub fn remove(&self, path: &str) -> SftpResult<()> {
        let mut buf = Buf::new();
        buf.put_str(path);
        let (t, data) = self.request(SSH_FXP_REMOVE, &buf.0)?;
        self.check_status(t, &data)
    }

    pub fn rename(&self, from: &str, to: &str) -> SftpResult<()> {
        let mut buf = Buf::new();
        buf.put_str(from);
        buf.put_str(to);
        let (t, data) = self.request(SSH_FXP_RENAME, &buf.0)?;
        self.check_status(t, &data)
    }

    pub fn symlink(&self, target: &str, link: &str) -> SftpResult<()> {
        let mut buf = Buf::new();
        buf.put_str(target);
        buf.put_str(link);
        let (t, data) = self.request(SSH_FXP_SYMLINK, &buf.0)?;
        self.check_status(t, &data)
    }

    // ── Convenience: open flags from POSIX ───────────────────────────

    pub fn open_flags_from_libc(flags: i32) -> u32 {
        let mut sf = 0u32;
        let accmode = flags & libc::O_ACCMODE;
        if accmode == libc::O_RDONLY {
            sf |= SSH_FXF_READ;
        }
        if accmode == libc::O_WRONLY {
            sf |= SSH_FXF_WRITE;
        }
        if accmode == libc::O_RDWR {
            sf |= SSH_FXF_READ | SSH_FXF_WRITE;
        }
        if flags & libc::O_CREAT != 0 {
            sf |= SSH_FXF_CREAT;
        }
        if flags & libc::O_TRUNC != 0 {
            sf |= SSH_FXF_TRUNC;
        }
        if flags & libc::O_EXCL != 0 {
            sf |= SSH_FXF_EXCL;
        }
        if flags & libc::O_APPEND != 0 {
            sf |= SSH_FXF_APPEND;
        }
        sf
    }
}

pub(crate) fn build_ssh_args(
    host: &str,
    port: u16,
    user: Option<&str>,
    identity: Option<&str>,
    accept_new_host_key: bool,
) -> SftpResult<Vec<String>> {
    validate_ssh_target(user, host)?;

    let mut args = vec![
        "-oServerAliveInterval=15".to_string(),
        "-oServerAliveCountMax=3".to_string(),
        "-oBatchMode=yes".to_string(),
    ];
    if accept_new_host_key {
        args.push("-oStrictHostKeyChecking=accept-new".to_string());
    }
    if port != 22 {
        args.push("-p".to_string());
        args.push(port.to_string());
    }
    if let Some(id) = identity {
        args.push("-i".to_string());
        args.push(id.to_string());
    }

    let target = match user {
        Some(u) => format!("{u}@{host}"),
        None => host.to_string(),
    };
    args.push("-s".to_string());
    args.push("--".to_string());
    args.push(target);
    args.push("sftp".to_string());
    Ok(args)
}

pub(crate) fn validate_ssh_target(user: Option<&str>, host: &str) -> SftpResult<()> {
    if host.is_empty() || host.starts_with('-') || has_control_char(host) {
        return Err(SftpError::Protocol("invalid SSH host".into()));
    }
    if let Some(user) = user {
        if user.is_empty() || user.starts_with('-') || has_control_char(user) {
            return Err(SftpError::Protocol("invalid SSH user".into()));
        }
    }
    Ok(())
}

fn has_control_char(value: &str) -> bool {
    value.chars().any(|c| c == '\0' || c.is_control())
}

impl Drop for SftpSession {
    fn drop(&mut self) {
        if let Ok(mut guard) = self._child.lock() {
            if let Some(ref mut child) = *guard {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}
