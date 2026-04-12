//! FUSE filesystem that translates VFS operations to SFTP calls.

use crate::sftp::{FileAttr, SftpError, SftpSession};
use fuser::{
    FileAttr as FuseAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory,
    ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request, TimeOrNow,
};
use libc::{EACCES, ECONNABORTED, EIO, ENOENT, EPERM};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(30);
const BLOCK_SIZE: u32 = 512;

// ── Inode management ─────────────────────────────────────────────────
// FUSE uses integer inodes. We map remote paths <-> inodes.

struct InodeTable {
    path_to_ino: HashMap<String, u64>,
    ino_to_path: HashMap<u64, String>,
    next_ino: AtomicU64,
}

impl InodeTable {
    fn new(root_path: &str) -> Self {
        let mut t = InodeTable {
            path_to_ino: HashMap::new(),
            ino_to_path: HashMap::new(),
            next_ino: AtomicU64::new(2), // 1 = root
        };
        t.path_to_ino.insert(root_path.to_string(), 1);
        t.ino_to_path.insert(1, root_path.to_string());
        t
    }

    fn get_or_insert(&mut self, path: &str) -> u64 {
        if let Some(&ino) = self.path_to_ino.get(path) {
            return ino;
        }
        let ino = self.next_ino.fetch_add(1, Ordering::Relaxed);
        self.path_to_ino.insert(path.to_string(), ino);
        self.ino_to_path.insert(ino, path.to_string());
        ino
    }

    fn get_path(&self, ino: u64) -> Option<&str> {
        self.ino_to_path.get(&ino).map(|s| s.as_str())
    }

    fn remove_path(&mut self, path: &str) {
        if let Some(ino) = self.path_to_ino.remove(path) {
            self.ino_to_path.remove(&ino);
        }
    }

    fn rename(&mut self, old: &str, new: &str) {
        if let Some(ino) = self.path_to_ino.remove(old) {
            self.ino_to_path.insert(ino, new.to_string());
            self.path_to_ino.insert(new.to_string(), ino);
        }
    }
}

// ── Open file handle ─────────────────────────────────────────────────

struct OpenFile {
    handle: Vec<u8>, // SFTP server's opaque file handle
}

// ── Convert types ────────────────────────────────────────────────────

fn sftp_attr_to_fuse(ino: u64, a: &FileAttr) -> FuseAttr {
    let kind = if (a.perm & 0o170000) == 0o120000 {
        FileType::Symlink
    } else if a.perm & 0o40000 != 0 {
        FileType::Directory
    } else {
        FileType::RegularFile
    };

    FuseAttr {
        ino,
        size: a.size,
        blocks: (a.size + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64,
        atime: UNIX_EPOCH + Duration::from_secs(a.atime as u64),
        mtime: UNIX_EPOCH + Duration::from_secs(a.mtime as u64),
        ctime: UNIX_EPOCH + Duration::from_secs(a.mtime as u64),
        crtime: UNIX_EPOCH,
        kind,
        perm: (a.perm & 0o7777) as u16,
        nlink: if kind == FileType::Directory { 2 } else { 1 },
        uid: a.uid,
        gid: a.gid,
        rdev: 0,
        blksize: BLOCK_SIZE,
        flags: 0,
    }
}

fn sftp_err_to_errno(e: &SftpError) -> i32 {
    match e {
        SftpError::Status(2, _) => ENOENT,
        SftpError::Status(3, _) => EACCES,
        SftpError::Status(4, _) => EPERM,
        SftpError::Status(7, _) => ECONNABORTED,
        SftpError::Disconnected => ECONNABORTED,
        _ => EIO,
    }
}

fn join_path(parent: &str, name: &str) -> String {
    if parent.ends_with('/') {
        format!("{parent}{name}")
    } else {
        format!("{parent}/{name}")
    }
}

// ── FUSE filesystem ─────────────────────────────────────────────────

pub struct SshFilesystem {
    sftp: Arc<SftpSession>,
    inodes: Mutex<InodeTable>,
    open_files: Mutex<HashMap<u64, OpenFile>>,
    next_fh: AtomicU64,
}

impl SshFilesystem {
    pub fn new(sftp: Arc<SftpSession>, root_path: &str) -> Self {
        SshFilesystem {
            sftp,
            inodes: Mutex::new(InodeTable::new(root_path)),
            open_files: Mutex::new(HashMap::new()),
            next_fh: AtomicU64::new(1),
        }
    }

    fn resolve(&self, ino: u64) -> Option<String> {
        self.inodes
            .lock()
            .unwrap()
            .get_path(ino)
            .map(|s| s.to_string())
    }

    fn alloc_fh(&self) -> u64 {
        self.next_fh.fetch_add(1, Ordering::Relaxed)
    }
}

impl Filesystem for SshFilesystem {
    fn getattr(&mut self, _req: &Request, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let path = match self.resolve(ino) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        match self.sftp.lstat(&path) {
            Ok(a) => reply.attr(&TTL, &sftp_attr_to_fuse(ino, &a)),
            Err(e) => reply.error(sftp_err_to_errno(&e)),
        }
    }

    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let parent_path = match self.resolve(parent) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        let child_name = name.to_string_lossy();
        let child_path = join_path(&parent_path, &child_name);

        match self.sftp.lstat(&child_path) {
            Ok(a) => {
                let ino = self.inodes.lock().unwrap().get_or_insert(&child_path);
                reply.entry(&TTL, &sftp_attr_to_fuse(ino, &a), 0);
            }
            Err(e) => reply.error(sftp_err_to_errno(&e)),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let path = match self.resolve(ino) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };

        let entries = match self.sftp.readdir(&path) {
            Ok(e) => e,
            Err(e) => {
                reply.error(sftp_err_to_errno(&e));
                return;
            }
        };

        // Synthesize . and ..
        let mut all: Vec<(String, FileType, u64)> = vec![
            (".".into(), FileType::Directory, ino),
            ("..".into(), FileType::Directory, 1),
        ];

        let mut inodes = self.inodes.lock().unwrap();
        for entry in &entries {
            let child_path = join_path(&path, &entry.name);
            let child_ino = inodes.get_or_insert(&child_path);
            let kind = if (entry.attrs.perm & 0o170000) == 0o120000 {
                FileType::Symlink
            } else if entry.attrs.perm & 0o40000 != 0 {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            all.push((entry.name.clone(), kind, child_ino));
        }
        drop(inodes);

        for (i, (name, kind, ino)) in all.iter().enumerate().skip(offset as usize) {
            if reply.add(*ino, (i + 1) as i64, *kind, name) {
                break; // buffer full
            }
        }
        reply.ok();
    }

    fn open(&mut self, _req: &Request, ino: u64, flags: i32, reply: ReplyOpen) {
        let path = match self.resolve(ino) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        let sf = SftpSession::open_flags_from_libc(flags);
        match self.sftp.open(&path, sf, 0) {
            Ok(handle) => {
                let fh = self.alloc_fh();
                self.open_files
                    .lock()
                    .unwrap()
                    .insert(fh, OpenFile { handle });
                reply.opened(fh, 0);
            }
            Err(e) => reply.error(sftp_err_to_errno(&e)),
        }
    }

    fn release(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        if let Some(of) = self.open_files.lock().unwrap().remove(&fh) {
            let _ = self.sftp.close(&of.handle);
        }
        reply.ok();
    }

    fn read(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let handle = {
            let files = self.open_files.lock().unwrap();
            match files.get(&fh) {
                Some(f) => f.handle.clone(),
                None => {
                    reply.error(EIO);
                    return;
                }
            }
        };
        match self.sftp.read(&handle, offset as u64, size) {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(sftp_err_to_errno(&e)),
        }
    }

    fn write(
        &mut self,
        _req: &Request,
        _ino: u64,
        fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let handle = {
            let files = self.open_files.lock().unwrap();
            match files.get(&fh) {
                Some(f) => f.handle.clone(),
                None => {
                    reply.error(EIO);
                    return;
                }
            }
        };
        match self.sftp.write(&handle, offset as u64, data) {
            Ok(()) => reply.written(data.len() as u32),
            Err(e) => reply.error(sftp_err_to_errno(&e)),
        }
    }

    fn create(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let parent_path = match self.resolve(parent) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        let child_name = name.to_string_lossy();
        let path = join_path(&parent_path, &child_name);

        let sf = SftpSession::open_flags_from_libc(flags) | crate::sftp::SSH_FXF_CREAT;
        match self.sftp.open(&path, sf, mode) {
            Ok(handle) => {
                let ino = self.inodes.lock().unwrap().get_or_insert(&path);
                let fh = self.alloc_fh();
                self.open_files
                    .lock()
                    .unwrap()
                    .insert(fh, OpenFile { handle });

                let attr = self.sftp.lstat(&path).unwrap_or_else(|_| {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as u32;
                    FileAttr {
                        size: 0,
                        uid: 0,
                        gid: 0,
                        perm: mode,
                        atime: now,
                        mtime: now,
                    }
                });
                reply.created(&TTL, &sftp_attr_to_fuse(ino, &attr), 0, fh, 0);
            }
            Err(e) => reply.error(sftp_err_to_errno(&e)),
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let parent_path = match self.resolve(parent) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        let path = join_path(&parent_path, &name.to_string_lossy());

        match self.sftp.mkdir(&path, mode) {
            Ok(()) => match self.sftp.lstat(&path) {
                Ok(a) => {
                    let ino = self.inodes.lock().unwrap().get_or_insert(&path);
                    reply.entry(&TTL, &sftp_attr_to_fuse(ino, &a), 0);
                }
                Err(e) => reply.error(sftp_err_to_errno(&e)),
            },
            Err(e) => reply.error(sftp_err_to_errno(&e)),
        }
    }

    fn unlink(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let parent_path = match self.resolve(parent) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        let path = join_path(&parent_path, &name.to_string_lossy());
        match self.sftp.remove(&path) {
            Ok(()) => {
                self.inodes.lock().unwrap().remove_path(&path);
                reply.ok();
            }
            Err(e) => reply.error(sftp_err_to_errno(&e)),
        }
    }

    fn rmdir(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let parent_path = match self.resolve(parent) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        let path = join_path(&parent_path, &name.to_string_lossy());
        match self.sftp.rmdir(&path) {
            Ok(()) => {
                self.inodes.lock().unwrap().remove_path(&path);
                reply.ok();
            }
            Err(e) => reply.error(sftp_err_to_errno(&e)),
        }
    }

    fn rename(
        &mut self,
        _req: &Request,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let old_parent = match self.resolve(parent) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        let new_parent = match self.resolve(newparent) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };
        let old_path = join_path(&old_parent, &name.to_string_lossy());
        let new_path = join_path(&new_parent, &newname.to_string_lossy());

        match self.sftp.rename(&old_path, &new_path) {
            Ok(()) => {
                self.inodes.lock().unwrap().rename(&old_path, &new_path);
                reply.ok();
            }
            Err(e) => reply.error(sftp_err_to_errno(&e)),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let path = match self.resolve(ino) {
            Some(p) => p,
            None => {
                reply.error(ENOENT);
                return;
            }
        };

        // Get current attrs first
        let mut attrs = match self.sftp.lstat(&path) {
            Ok(a) => a,
            Err(e) => {
                reply.error(sftp_err_to_errno(&e));
                return;
            }
        };

        if let Some(m) = mode {
            attrs.perm = m;
        }
        if let Some(u) = uid {
            attrs.uid = u;
        }
        if let Some(g) = gid {
            attrs.gid = g;
        }
        if let Some(s) = size {
            attrs.size = s;
        }

        let now = || {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as u32
        };
        if let Some(t) = atime {
            attrs.atime = match t {
                TimeOrNow::SpecificTime(t) => {
                    t.duration_since(UNIX_EPOCH).unwrap().as_secs() as u32
                }
                TimeOrNow::Now => now(),
            };
        }
        if let Some(t) = mtime {
            attrs.mtime = match t {
                TimeOrNow::SpecificTime(t) => {
                    t.duration_since(UNIX_EPOCH).unwrap().as_secs() as u32
                }
                TimeOrNow::Now => now(),
            };
        }

        // Handle truncation: need to open, truncate, close
        if size.is_some() {
            let sf = crate::sftp::SftpSession::open_flags_from_libc(libc::O_WRONLY);
            if let Ok(handle) = self
                .sftp
                .open(&path, sf | crate::sftp::SSH_FXF_TRUNC, attrs.perm)
            {
                let _ = self.sftp.close(&handle);
            }
        }

        match self.sftp.setstat(&path, &attrs) {
            Ok(()) => reply.attr(&TTL, &sftp_attr_to_fuse(ino, &attrs)),
            Err(_) => {
                // Some servers reject setstat partially; re-read attrs
                match self.sftp.lstat(&path) {
                    Ok(a) => reply.attr(&TTL, &sftp_attr_to_fuse(ino, &a)),
                    Err(e) => reply.error(sftp_err_to_errno(&e)),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sftp::{FileAttr, SftpError};

    #[test]
    fn join_path_no_trailing_slash() {
        assert_eq!(join_path("/home/user", "file.txt"), "/home/user/file.txt");
    }

    #[test]
    fn join_path_with_trailing_slash() {
        assert_eq!(join_path("/home/user/", "file.txt"), "/home/user/file.txt");
    }

    #[test]
    fn join_path_root() {
        assert_eq!(join_path("/", "etc"), "/etc");
    }

    #[test]
    fn sftp_attr_to_fuse_regular_file() {
        let attr = FileAttr {
            size: 4096,
            uid: 1000,
            gid: 1000,
            perm: 0o100644,
            atime: 1000,
            mtime: 2000,
        };
        let fuse = sftp_attr_to_fuse(10, &attr);
        assert_eq!(fuse.ino, 10);
        assert_eq!(fuse.kind, FileType::RegularFile);
        assert_eq!(fuse.perm, 0o644);
        assert_eq!(fuse.size, 4096);
        assert_eq!(fuse.nlink, 1);
    }

    #[test]
    fn sftp_attr_to_fuse_directory() {
        let attr = FileAttr {
            size: 0,
            uid: 0,
            gid: 0,
            perm: 0o40755,
            atime: 0,
            mtime: 0,
        };
        let fuse = sftp_attr_to_fuse(2, &attr);
        assert_eq!(fuse.kind, FileType::Directory);
        assert_eq!(fuse.perm, 0o755);
        assert_eq!(fuse.nlink, 2);
    }

    #[test]
    fn sftp_attr_to_fuse_symlink() {
        let attr = FileAttr {
            size: 10,
            uid: 0,
            gid: 0,
            perm: 0o120777,
            atime: 0,
            mtime: 0,
        };
        let fuse = sftp_attr_to_fuse(5, &attr);
        assert_eq!(fuse.kind, FileType::Symlink);
        assert_eq!(fuse.nlink, 1);
    }

    #[test]
    fn sftp_attr_to_fuse_symlink_not_confused_with_regular() {
        // With the old buggy mask (0o120000), a regular file with group execute
        // could be misdetected. Ensure the full type mask (0o170000) works.
        let attr = FileAttr {
            size: 100,
            uid: 0,
            gid: 0,
            perm: 0o100755, // regular file, not symlink
            atime: 0,
            mtime: 0,
        };
        let fuse = sftp_attr_to_fuse(6, &attr);
        assert_eq!(fuse.kind, FileType::RegularFile);
    }

    #[test]
    fn sftp_err_to_errno_no_such_file() {
        let e = SftpError::Status(2, "No such file".into());
        assert_eq!(sftp_err_to_errno(&e), ENOENT);
    }

    #[test]
    fn sftp_err_to_errno_permission_denied() {
        let e = SftpError::Status(3, "Permission denied".into());
        assert_eq!(sftp_err_to_errno(&e), EACCES);
    }

    #[test]
    fn sftp_err_to_errno_failure() {
        let e = SftpError::Status(4, "Failure".into());
        assert_eq!(sftp_err_to_errno(&e), EPERM);
    }

    #[test]
    fn sftp_err_to_errno_disconnected() {
        let e = SftpError::Disconnected;
        assert_eq!(sftp_err_to_errno(&e), ECONNABORTED);
    }

    #[test]
    fn sftp_err_to_errno_generic() {
        let e = SftpError::Protocol("something".into());
        assert_eq!(sftp_err_to_errno(&e), EIO);
    }

    #[test]
    fn inode_table_root() {
        let t = InodeTable::new("/home");
        assert_eq!(t.get_path(1), Some("/home"));
    }

    #[test]
    fn inode_table_get_or_insert() {
        let mut t = InodeTable::new("/");
        let ino1 = t.get_or_insert("/etc");
        let ino2 = t.get_or_insert("/etc");
        assert_eq!(ino1, ino2);
        assert_eq!(t.get_path(ino1), Some("/etc"));

        let ino3 = t.get_or_insert("/var");
        assert_ne!(ino1, ino3);
    }

    #[test]
    fn inode_table_remove() {
        let mut t = InodeTable::new("/");
        let ino = t.get_or_insert("/tmp/file");
        assert!(t.get_path(ino).is_some());
        t.remove_path("/tmp/file");
        assert!(t.get_path(ino).is_none());
    }

    #[test]
    fn inode_table_rename() {
        let mut t = InodeTable::new("/");
        let ino = t.get_or_insert("/old");
        t.rename("/old", "/new");
        assert_eq!(t.get_path(ino), Some("/new"));
        // Old path should be gone
        assert!(t.path_to_ino.get("/old").is_none());
    }
}
