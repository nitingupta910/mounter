//! SFTP wire protocol constants.

// ── SFTP protocol constants ──────────────────────────────────────────

// Packet types
pub(crate) const SSH_FXP_INIT: u8 = 1;
pub(crate) const SSH_FXP_VERSION: u8 = 2;
pub(crate) const SSH_FXP_OPEN: u8 = 3;
pub(crate) const SSH_FXP_CLOSE: u8 = 4;
pub(crate) const SSH_FXP_READ: u8 = 5;
pub(crate) const SSH_FXP_WRITE: u8 = 6;
pub(crate) const SSH_FXP_LSTAT: u8 = 7;
pub(crate) const SSH_FXP_SETSTAT: u8 = 9;
pub(crate) const SSH_FXP_OPENDIR: u8 = 11;
pub(crate) const SSH_FXP_READDIR: u8 = 12;
pub(crate) const SSH_FXP_REMOVE: u8 = 13;
pub(crate) const SSH_FXP_MKDIR: u8 = 14;
pub(crate) const SSH_FXP_RMDIR: u8 = 15;
pub(crate) const SSH_FXP_REALPATH: u8 = 16;
pub(crate) const SSH_FXP_STAT: u8 = 17;
pub(crate) const SSH_FXP_RENAME: u8 = 18;
pub(crate) const SSH_FXP_SYMLINK: u8 = 20;

// Response types
pub(crate) const SSH_FXP_STATUS: u8 = 101;
pub(crate) const SSH_FXP_HANDLE: u8 = 102;
pub(crate) const SSH_FXP_DATA: u8 = 103;
pub(crate) const SSH_FXP_NAME: u8 = 104;
pub(crate) const SSH_FXP_ATTRS: u8 = 105;

// Status codes
pub(crate) const SSH_FX_OK: u32 = 0;
pub(crate) const SSH_FX_EOF: u32 = 1;

// Attribute flags
pub(crate) const SSH_FILEXFER_ATTR_SIZE: u32 = 0x0000_0001;
pub(crate) const SSH_FILEXFER_ATTR_UIDGID: u32 = 0x0000_0002;
pub(crate) const SSH_FILEXFER_ATTR_PERMISSIONS: u32 = 0x0000_0004;
pub(crate) const SSH_FILEXFER_ATTR_ACMODTIME: u32 = 0x0000_0008;
pub(crate) const SSH_FILEXFER_ATTR_EXTENDED: u32 = 0x8000_0000;

// Open flags
pub const SSH_FXF_READ: u32 = 0x0000_0001;
pub const SSH_FXF_WRITE: u32 = 0x0000_0002;
pub const SSH_FXF_CREAT: u32 = 0x0000_0008;
pub const SSH_FXF_TRUNC: u32 = 0x0000_0010;
pub const SSH_FXF_EXCL: u32 = 0x0000_0020;
pub const SSH_FXF_APPEND: u32 = 0x0000_0004;

pub(crate) const SFTP_PROTO_VERSION: u32 = 3;
pub(crate) const MAX_READ_SIZE: u32 = 262144; // 256KB — most servers support this
pub(crate) const MAX_WRITE_SIZE: u32 = 262144;
pub(crate) const READ_PIPELINE: usize = 8; // concurrent READ requests
