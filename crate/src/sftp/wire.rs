//! SFTP buffer encoding and decoding.

use super::protocol::*;
use super::types::{FileAttr, SftpError, SftpResult};

// ── Buffer helpers (SFTP wire format) ────────────────────────────────

pub(crate) struct Buf(pub(crate) Vec<u8>);

impl Buf {
    pub(crate) fn new() -> Self {
        Buf(Vec::with_capacity(256))
    }
    pub(crate) fn with_capacity(n: usize) -> Self {
        Buf(Vec::with_capacity(n))
    }

    pub(crate) fn put_u8(&mut self, v: u8) {
        self.0.push(v);
    }
    pub(crate) fn put_u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    pub(crate) fn put_u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }
    pub(crate) fn put_str(&mut self, s: &str) {
        self.put_u32(s.len() as u32);
        self.0.extend_from_slice(s.as_bytes());
    }
    pub(crate) fn put_bytes(&mut self, b: &[u8]) {
        self.put_u32(b.len() as u32);
        self.0.extend_from_slice(b);
    }
    pub(crate) fn put_attrs(&mut self, attrs: &FileAttr) {
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

pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub(crate) fn get_u8(&mut self) -> SftpResult<u8> {
        if self.pos >= self.data.len() {
            return Err(SftpError::Protocol("buffer underflow".into()));
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub(crate) fn get_u32(&mut self) -> SftpResult<u32> {
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

    pub(crate) fn get_u64(&mut self) -> SftpResult<u64> {
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

    pub(crate) fn get_bytes(&mut self) -> SftpResult<Vec<u8>> {
        let len = self.get_u32()? as usize;
        if self.pos + len > self.data.len() {
            return Err(SftpError::Protocol("buffer underflow".into()));
        }
        let v = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }

    pub(crate) fn get_string(&mut self) -> SftpResult<String> {
        let b = self.get_bytes()?;
        String::from_utf8(b).map_err(|e| SftpError::Protocol(format!("invalid UTF-8: {e}")))
    }

    pub(crate) fn get_attrs(&mut self) -> SftpResult<FileAttr> {
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
