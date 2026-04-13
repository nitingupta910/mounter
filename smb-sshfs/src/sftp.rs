//! SFTP protocol implementation over an SSH subprocess.
//!
//! Spawns `ssh -s sftp` and speaks the binary SFTP protocol over pipes.
//! No SSH library needed — uses the system's ssh binary (keys, config, agent all work).

use std::io::{self, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

// ── SFTP protocol constants ──────────────────────────────────────────

// Packet types
const SSH_FXP_INIT: u8 = 1;
const SSH_FXP_VERSION: u8 = 2;
const SSH_FXP_OPEN: u8 = 3;
const SSH_FXP_CLOSE: u8 = 4;
const SSH_FXP_READ: u8 = 5;
const SSH_FXP_WRITE: u8 = 6;
const SSH_FXP_LSTAT: u8 = 7;
const SSH_FXP_SETSTAT: u8 = 9;
const SSH_FXP_OPENDIR: u8 = 11;
const SSH_FXP_READDIR: u8 = 12;
const SSH_FXP_REMOVE: u8 = 13;
const SSH_FXP_MKDIR: u8 = 14;
const SSH_FXP_RMDIR: u8 = 15;
const SSH_FXP_REALPATH: u8 = 16;
const SSH_FXP_STAT: u8 = 17;
const SSH_FXP_RENAME: u8 = 18;
const SSH_FXP_SYMLINK: u8 = 20;

// Response types
const SSH_FXP_STATUS: u8 = 101;
const SSH_FXP_HANDLE: u8 = 102;
const SSH_FXP_DATA: u8 = 103;
const SSH_FXP_NAME: u8 = 104;
const SSH_FXP_ATTRS: u8 = 105;

// Status codes
const SSH_FX_OK: u32 = 0;
const SSH_FX_EOF: u32 = 1;

// Attribute flags
const SSH_FILEXFER_ATTR_SIZE: u32 = 0x0000_0001;
const SSH_FILEXFER_ATTR_UIDGID: u32 = 0x0000_0002;
const SSH_FILEXFER_ATTR_PERMISSIONS: u32 = 0x0000_0004;
const SSH_FILEXFER_ATTR_ACMODTIME: u32 = 0x0000_0008;
const SSH_FILEXFER_ATTR_EXTENDED: u32 = 0x8000_0000;

// Open flags
const SSH_FXF_READ: u32 = 0x0000_0001;
const SSH_FXF_WRITE: u32 = 0x0000_0002;
pub const SSH_FXF_CREAT: u32 = 0x0000_0008;
pub const SSH_FXF_TRUNC: u32 = 0x0000_0010;
const SSH_FXF_EXCL: u32 = 0x0000_0020;
const SSH_FXF_APPEND: u32 = 0x0000_0004;

const SFTP_PROTO_VERSION: u32 = 3;
const MAX_READ_SIZE: u32 = 262144; // 256KB — most servers support this
const MAX_WRITE_SIZE: u32 = 262144;
const READDIR_PIPELINE: usize = 8; // concurrent READDIR requests

// ── Types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FileAttr {
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub perm: u32,
    pub atime: u32,
    pub mtime: u32,
}

impl Default for FileAttr {
    fn default() -> Self {
        Self {
            size: 0,
            uid: 0,
            gid: 0,
            perm: 0o644,
            atime: 0,
            mtime: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub attrs: FileAttr,
}

pub type SftpResult<T> = Result<T, SftpError>;

#[derive(Debug)]
pub enum SftpError {
    Io(io::Error),
    Protocol(String),
    Status(u32, String),
    Disconnected,
}

impl From<io::Error> for SftpError {
    fn from(e: io::Error) -> Self {
        SftpError::Io(e)
    }
}

impl std::fmt::Display for SftpError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SftpError::Io(e) => write!(f, "IO: {e}"),
            SftpError::Protocol(s) => write!(f, "Protocol: {s}"),
            SftpError::Status(c, s) => write!(f, "SFTP status {c}: {s}"),
            SftpError::Disconnected => write!(f, "Disconnected"),
        }
    }
}

// ── Buffer helpers (SFTP wire format) ────────────────────────────────

struct Buf(Vec<u8>);

impl Buf {
    fn new() -> Self {
        Buf(Vec::with_capacity(256))
    }
    fn with_capacity(n: usize) -> Self {
        Buf(Vec::with_capacity(n))
    }

    fn put_u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn put_u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn put_u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    fn put_str(&mut self, s: &str) {
        self.put_u32(s.len() as u32);
        self.0.extend_from_slice(s.as_bytes());
    }
    fn put_bytes(&mut self, b: &[u8]) {
        self.put_u32(b.len() as u32);
        self.0.extend_from_slice(b);
    }
    fn put_attrs(&mut self, attrs: &FileAttr) {
        let mut flags = 0u32;
        flags |= SSH_FILEXFER_ATTR_SIZE;
        flags |= SSH_FILEXFER_ATTR_UIDGID;
        flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
        flags |= SSH_FILEXFER_ATTR_ACMODTIME;
        self.put_u32(flags);
        self.put_u64(attrs.size);
        self.put_u32(attrs.uid);
        self.put_u32(attrs.gid);
        self.put_u32(attrs.perm);
        self.put_u32(attrs.atime);
        self.put_u32(attrs.mtime);
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn get_u8(&mut self) -> SftpResult<u8> {
        if self.pos >= self.data.len() {
            return Err(SftpError::Protocol("buffer underflow".into()));
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn get_u32(&mut self) -> SftpResult<u32> {
        if self.pos + 4 > self.data.len() {
            return Err(SftpError::Protocol("buffer underflow".into()));
        }
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn get_u64(&mut self) -> SftpResult<u64> {
        if self.pos + 8 > self.data.len() {
            return Err(SftpError::Protocol("buffer underflow".into()));
        }
        let v = u64::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        self.pos += 8;
        Ok(v)
    }

    fn get_bytes(&mut self) -> SftpResult<Vec<u8>> {
        let len = self.get_u32()? as usize;
        if self.pos + len > self.data.len() {
            return Err(SftpError::Protocol("buffer underflow".into()));
        }
        let v = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }

    fn get_string(&mut self) -> SftpResult<String> {
        let b = self.get_bytes()?;
        String::from_utf8(b).map_err(|e| SftpError::Protocol(format!("invalid UTF-8: {e}")))
    }

    fn get_attrs(&mut self) -> SftpResult<FileAttr> {
        let flags = self.get_u32()?;
        let mut a = FileAttr::default();

        if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
            a.size = self.get_u64()?;
        }
        if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
            a.uid = self.get_u32()?;
            a.gid = self.get_u32()?;
        }
        if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
            a.perm = self.get_u32()?;
        }
        if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
            a.atime = self.get_u32()?;
            a.mtime = self.get_u32()?;
        }
        if flags & SSH_FILEXFER_ATTR_EXTENDED != 0 {
            let count = self.get_u32()?;
            for _ in 0..count {
                let _ = self.get_bytes()?; // name
                let _ = self.get_bytes()?; // value
            }
        }
        Ok(a)
    }
}

// ── SFTP Session ─────────────────────────────────────────────────────

pub struct SftpSession {
    reader: Mutex<Box<dyn Read + Send>>,
    writer: Mutex<Box<dyn Write + Send>>,
    next_id: AtomicU32,
    _child: Mutex<Option<Child>>,
}

impl SftpSession {
    /// Connect to remote host by spawning `ssh -s sftp`.
    pub fn connect(
        host: &str,
        port: u16,
        user: Option<&str>,
        identity: Option<&str>,
    ) -> SftpResult<Self> {
        let (our_sock, child_sock) = UnixStream::pair()?;

        let mut cmd = Command::new("ssh");
        cmd.arg("-oStrictHostKeyChecking=accept-new")
            .arg("-oServerAliveInterval=15")
            .arg("-oServerAliveCountMax=3")
            .arg("-oBatchMode=yes");

        if port != 22 {
            cmd.arg("-p").arg(port.to_string());
        }
        if let Some(id) = identity {
            cmd.arg("-i").arg(id);
        }

        let target = match user {
            Some(u) => format!("{u}@{host}"),
            None => host.to_string(),
        };
        cmd.arg(&target).arg("-s").arg("sftp");

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
    fn write_packet(w: &mut dyn Write, pkt_type: u8, id: u32, payload: &[u8]) -> SftpResult<()> {
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
            return Err(SftpError::Protocol(format!("bad packet length: {len}")));
        }
        let mut data = vec![0u8; len];
        r.read_exact(&mut data)
            .map_err(|_| SftpError::Disconnected)?;
        Ok((data[0], data[1..].to_vec()))
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
        if resp_type != SSH_FXP_VERSION && resp_data.len() >= 4 {
            let resp_id =
                u32::from_be_bytes([resp_data[0], resp_data[1], resp_data[2], resp_data[3]]);
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

        // Pipelined READDIR: send READDIR_PIPELINE requests at once, then read
        // responses. Keeps the network saturated instead of waiting for each
        // response before sending the next request.
        let mut entries = Vec::new();
        let mut eof = false;
        let mut pending: usize = 0;

        // Prime the pipeline — send initial batch
        {
            let mut w = self.writer.lock().map_err(|_| SftpError::Disconnected)?;
            for _ in 0..READDIR_PIPELINE {
                let id = self.next_id();
                let mut rbuf = Buf::new();
                rbuf.put_bytes(&handle);
                Self::write_packet(&mut *w, SSH_FXP_READDIR, id, &rbuf.0)?;
                pending += 1;
            }
            w.flush().map_err(|_| SftpError::Disconnected)?;
        }

        // Read responses, refilling pipeline as we go
        while pending > 0 {
            let (t, data) = self.recv()?;
            pending -= 1;

            if t == SSH_FXP_STATUS {
                let mut sr = Reader::new(&data[4..]);
                let code = sr.get_u32()?;
                if code == SSH_FX_EOF {
                    eof = true;
                    continue; // drain remaining pending responses
                }
                let msg = sr.get_string().unwrap_or_default();
                let _ = self.close_handle(&handle);
                return Err(SftpError::Status(code, msg));
            }

            if t != SSH_FXP_NAME {
                let _ = self.close_handle(&handle);
                return Err(SftpError::Protocol(format!("expected NAME, got {t}")));
            }

            // Parse entries from this batch
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

            // Keep pipeline full: send another request if not EOF
            if !eof {
                let mut w = self.writer.lock().map_err(|_| SftpError::Disconnected)?;
                let id = self.next_id();
                let mut rbuf = Buf::new();
                rbuf.put_bytes(&handle);
                Self::write_packet(&mut *w, SSH_FXP_READDIR, id, &rbuf.0)?;
                w.flush().map_err(|_| SftpError::Disconnected)?;
                pending += 1;
            }
        }

        self.close_handle(&handle)?;
        Ok(entries)
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
        // Pipeline multiple 256KB reads to saturate the network.
        let total = len as u64;
        if total <= MAX_READ_SIZE as u64 {
            return self.read_single(handle, offset, len);
        }

        let mut result = Vec::with_capacity(total as usize);
        let mut cur_offset = offset;
        let end = offset + total;

        // Send all read requests up front (pipeline)
        let mut ids = Vec::new();
        {
            let mut w = self.writer.lock().map_err(|_| SftpError::Disconnected)?;
            while cur_offset < end {
                let chunk = ((end - cur_offset) as u32).min(MAX_READ_SIZE);
                let id = self.next_id();
                let mut buf = Buf::new();
                buf.put_bytes(handle);
                buf.put_u64(cur_offset);
                buf.put_u32(chunk);
                Self::write_packet(&mut *w, SSH_FXP_READ, id, &buf.0)?;
                ids.push(id);
                cur_offset += chunk as u64;
            }
            w.flush().map_err(|_| SftpError::Disconnected)?;
        }

        // Collect responses in order — must drain ALL responses to keep
        // the SFTP stream in sync, even on early EOF.
        let mut r = self.reader.lock().map_err(|_| SftpError::Disconnected)?;
        let mut eof = false;
        for _expected_id in &ids {
            let (t, data) = Self::read_packet(&mut *r)?;
            if eof {
                continue; // drain remaining responses
            }
            if t == SSH_FXP_STATUS {
                let mut sr = Reader::new(&data[4..]);
                let code = sr.get_u32()?;
                if code == SSH_FX_EOF {
                    eof = true;
                    continue; // drain remaining
                }
                // Real error — still drain remaining before returning
                let msg = sr.get_string().unwrap_or_default();
                // Drain the rest
                for _ in 0..ids.len().saturating_sub(1) {
                    let _ = Self::read_packet(&mut *r);
                }
                return Err(SftpError::Status(code, msg));
            }
            if t != SSH_FXP_DATA {
                return Err(SftpError::Protocol(format!("expected DATA, got {t}")));
            }
            let chunk = Reader::new(&data[4..]).get_bytes()?;
            if chunk.is_empty() {
                eof = true;
                continue;
            }
            result.extend_from_slice(&chunk);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buf_put_u32() {
        let mut buf = Buf::new();
        buf.put_u32(0x01020304);
        assert_eq!(buf.0, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn buf_put_str() {
        let mut buf = Buf::new();
        buf.put_str("abc");
        // 4-byte length (3) + 3 bytes "abc"
        assert_eq!(buf.0, vec![0, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn buf_put_bytes() {
        let mut buf = Buf::new();
        buf.put_bytes(&[0xDE, 0xAD]);
        assert_eq!(buf.0, vec![0, 0, 0, 2, 0xDE, 0xAD]);
    }

    #[test]
    fn buf_put_attrs() {
        let attrs = FileAttr {
            size: 1024,
            uid: 1000,
            gid: 1000,
            perm: 0o100644,
            atime: 1000000,
            mtime: 2000000,
        };
        let mut buf = Buf::new();
        buf.put_attrs(&attrs);

        let mut r = Reader::new(&buf.0);
        let flags = r.get_u32().unwrap();
        assert_eq!(
            flags,
            SSH_FILEXFER_ATTR_SIZE
                | SSH_FILEXFER_ATTR_UIDGID
                | SSH_FILEXFER_ATTR_PERMISSIONS
                | SSH_FILEXFER_ATTR_ACMODTIME
        );
        assert_eq!(r.get_u64().unwrap(), 1024);
        assert_eq!(r.get_u32().unwrap(), 1000); // uid
        assert_eq!(r.get_u32().unwrap(), 1000); // gid
        assert_eq!(r.get_u32().unwrap(), 0o100644); // perm
        assert_eq!(r.get_u32().unwrap(), 1000000); // atime
        assert_eq!(r.get_u32().unwrap(), 2000000); // mtime
    }

    #[test]
    fn reader_get_u32() {
        let data = [0x00, 0x00, 0x01, 0x00];
        let mut r = Reader::new(&data);
        assert_eq!(r.get_u32().unwrap(), 256);
    }

    #[test]
    fn reader_get_string() {
        let mut buf = Buf::new();
        buf.put_str("hello");
        let mut r = Reader::new(&buf.0);
        assert_eq!(r.get_string().unwrap(), "hello");
    }

    #[test]
    fn reader_get_attrs_roundtrip() {
        let original = FileAttr {
            size: 999,
            uid: 501,
            gid: 20,
            perm: 0o40755,
            atime: 12345,
            mtime: 67890,
        };
        let mut buf = Buf::new();
        buf.put_attrs(&original);

        let mut r = Reader::new(&buf.0);
        let parsed = r.get_attrs().unwrap();
        assert_eq!(parsed.size, original.size);
        assert_eq!(parsed.uid, original.uid);
        assert_eq!(parsed.gid, original.gid);
        assert_eq!(parsed.perm, original.perm);
        assert_eq!(parsed.atime, original.atime);
        assert_eq!(parsed.mtime, original.mtime);
    }

    #[test]
    fn reader_underflow() {
        let data = [0x00, 0x01];
        let mut r = Reader::new(&data);
        assert!(r.get_u32().is_err());
    }

    #[test]
    fn open_flags_rdonly() {
        let sf = SftpSession::open_flags_from_libc(libc::O_RDONLY);
        assert_eq!(sf, SSH_FXF_READ);
    }

    #[test]
    fn open_flags_wronly() {
        let sf = SftpSession::open_flags_from_libc(libc::O_WRONLY);
        assert_eq!(sf, SSH_FXF_WRITE);
    }

    #[test]
    fn open_flags_rdwr() {
        let sf = SftpSession::open_flags_from_libc(libc::O_RDWR);
        assert_eq!(sf, SSH_FXF_READ | SSH_FXF_WRITE);
    }

    #[test]
    fn open_flags_create_trunc() {
        let sf = SftpSession::open_flags_from_libc(libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC);
        assert!(sf & SSH_FXF_WRITE != 0);
        assert!(sf & SSH_FXF_CREAT != 0);
        assert!(sf & SSH_FXF_TRUNC != 0);
    }

    #[test]
    fn open_flags_append() {
        let sf = SftpSession::open_flags_from_libc(libc::O_WRONLY | libc::O_APPEND);
        assert!(sf & SSH_FXF_WRITE != 0);
        assert!(sf & SSH_FXF_APPEND != 0);
    }

    #[test]
    fn open_flags_excl() {
        let sf = SftpSession::open_flags_from_libc(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL);
        assert!(sf & SSH_FXF_WRITE != 0);
        assert!(sf & SSH_FXF_CREAT != 0);
        assert!(sf & SSH_FXF_EXCL != 0);
    }
}
