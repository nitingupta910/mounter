//! SFTP types and errors.

use std::io;

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
