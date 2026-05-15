//! Reconnecting SFTP wrapper with automatic retry.

use super::session::SftpSession;
use super::types::{DirEntry, FileAttr, SftpError, SftpResult};
use std::sync::Mutex;

// ── Reconnecting wrapper ─────────────────────────────────────────────
// Automatically reconnects the SFTP session on disconnect (sleep/wake,
// network change, remote reboot). Retries the failed operation once.

pub struct ReconnectingSftp {
    session: Mutex<Option<SftpSession>>,
    host: String,
    port: u16,
    user: Option<String>,
    identity: Option<String>,
    accept_new_host_key: bool,
}

impl ReconnectingSftp {
    #[cfg(test)]
    pub fn dummy() -> Self {
        ReconnectingSftp {
            session: Mutex::new(Some(SftpSession::dummy())),
            host: "test".into(),
            port: 22,
            user: None,
            identity: None,
            accept_new_host_key: false,
        }
    }

    pub fn connect(
        host: &str,
        port: u16,
        user: Option<&str>,
        identity: Option<&str>,
        accept_new_host_key: bool,
    ) -> SftpResult<Self> {
        let session = SftpSession::connect(host, port, user, identity, accept_new_host_key)?;
        Ok(ReconnectingSftp {
            session: Mutex::new(Some(session)),
            host: host.to_string(),
            port,
            user: user.map(|s| s.to_string()),
            identity: identity.map(|s| s.to_string()),
            accept_new_host_key,
        })
    }

    /// Try to reconnect. Returns true on success.
    fn reconnect(&self) -> bool {
        log::warn!("SFTP disconnected — reconnecting to {}...", self.host);
        let mut guard = match self.session.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        // Drop the old session (kills SSH process)
        *guard = None;

        match SftpSession::connect(
            &self.host,
            self.port,
            self.user.as_deref(),
            self.identity.as_deref(),
            self.accept_new_host_key,
        ) {
            Ok(new_session) => {
                log::info!("SFTP reconnected to {}", self.host);
                *guard = Some(new_session);
                true
            }
            Err(e) => {
                log::error!("SFTP reconnect failed: {e}");
                false
            }
        }
    }

    /// Execute an SFTP operation with automatic reconnect on disconnect.
    fn with_retry<T, F>(&self, op: F) -> SftpResult<T>
    where
        F: Fn(&SftpSession) -> SftpResult<T>,
    {
        // First attempt
        {
            let guard = self.session.lock().map_err(|_| SftpError::Disconnected)?;
            if let Some(ref session) = *guard {
                match op(session) {
                    // Disconnected or Protocol error = stream is dead/corrupt,
                    // reconnect to get a fresh session
                    Err(SftpError::Disconnected) | Err(SftpError::Protocol(_)) => {}
                    result => return result,
                }
            }
        }

        // Reconnect and retry once
        if !self.reconnect() {
            return Err(SftpError::Disconnected);
        }
        let guard = self.session.lock().map_err(|_| SftpError::Disconnected)?;
        match &*guard {
            Some(session) => op(session),
            None => Err(SftpError::Disconnected),
        }
    }

    /// Check if the session is currently connected.
    pub fn is_connected(&self) -> bool {
        self.session.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    // ── Public API (delegates to SftpSession with retry) ─────────────

    pub fn realpath(&self, path: &str) -> SftpResult<String> {
        self.with_retry(|s| s.realpath(path))
    }

    pub fn lstat(&self, path: &str) -> SftpResult<FileAttr> {
        self.with_retry(|s| s.lstat(path))
    }

    pub fn setstat(&self, path: &str, attrs: &FileAttr) -> SftpResult<()> {
        self.with_retry(|s| s.setstat(path, attrs))
    }

    pub fn readdir(&self, path: &str) -> SftpResult<Vec<DirEntry>> {
        self.with_retry(|s| s.readdir(path))
    }

    pub fn open(&self, path: &str, flags: u32, mode: u32) -> SftpResult<Vec<u8>> {
        self.with_retry(|s| s.open(path, flags, mode))
    }

    pub fn close(&self, handle: &[u8]) -> SftpResult<()> {
        // Don't retry close — handle is invalid after reconnect anyway
        let guard = self.session.lock().map_err(|_| SftpError::Disconnected)?;
        match &*guard {
            Some(session) => session.close(handle),
            None => Ok(()), // silently succeed — nothing to close
        }
    }

    pub fn read(&self, handle: &[u8], offset: u64, len: u32) -> SftpResult<Vec<u8>> {
        // Can't retry reads — the handle is tied to the old session.
        // Caller must reopen the file on Disconnected.
        let guard = self.session.lock().map_err(|_| SftpError::Disconnected)?;
        match &*guard {
            Some(session) => session.read(handle, offset, len),
            None => Err(SftpError::Disconnected),
        }
    }

    pub fn write(&self, handle: &[u8], offset: u64, data: &[u8]) -> SftpResult<()> {
        // Same as read — handle-based ops can't be retried across reconnects
        let guard = self.session.lock().map_err(|_| SftpError::Disconnected)?;
        match &*guard {
            Some(session) => session.write(handle, offset, data),
            None => Err(SftpError::Disconnected),
        }
    }

    pub fn mkdir(&self, path: &str, mode: u32) -> SftpResult<()> {
        self.with_retry(|s| s.mkdir(path, mode))
    }

    pub fn rmdir(&self, path: &str) -> SftpResult<()> {
        self.with_retry(|s| s.rmdir(path))
    }

    pub fn remove(&self, path: &str) -> SftpResult<()> {
        self.with_retry(|s| s.remove(path))
    }

    pub fn rename(&self, from: &str, to: &str) -> SftpResult<()> {
        self.with_retry(|s| s.rename(from, to))
    }
}
