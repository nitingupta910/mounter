//! SMB2 protocol constants.

// ── Protocol constants ──────────────────────────────────────────────

pub const SMB2_MAGIC: &[u8; 4] = b"\xfeSMB";
pub const SMB1_MAGIC: &[u8; 4] = b"\xffSMB";
pub const SMB2_HEADER_SIZE: usize = 64;

// Commands
pub const SMB2_NEGOTIATE: u16 = 0x0000;
pub const SMB2_SESSION_SETUP: u16 = 0x0001;
pub const SMB2_LOGOFF: u16 = 0x0002;
pub const SMB2_TREE_CONNECT: u16 = 0x0003;
pub const SMB2_TREE_DISCONNECT: u16 = 0x0004;
pub const SMB2_CREATE: u16 = 0x0005;
pub const SMB2_CLOSE: u16 = 0x0006;
pub const SMB2_FLUSH: u16 = 0x0007;
pub const SMB2_READ: u16 = 0x0008;
pub const SMB2_WRITE: u16 = 0x0009;
pub const SMB2_LOCK: u16 = 0x000A;
pub const SMB2_IOCTL: u16 = 0x000B;
pub const SMB2_QUERY_DIRECTORY: u16 = 0x000E;
pub const SMB2_QUERY_INFO: u16 = 0x0010;
pub const SMB2_SET_INFO: u16 = 0x0011;

// Dialects
pub const SMB2_DIALECT_202: u16 = 0x0202;
pub const SMB2_DIALECT_210: u16 = 0x0210;
pub const SMB2_DIALECT_300: u16 = 0x0300;
pub const SMB2_DIALECT_302: u16 = 0x0302;
pub const SMB2_DIALECT_311: u16 = 0x0311;

// Status codes
pub const STATUS_SUCCESS: u32 = 0x0000_0000;
pub const STATUS_MORE_PROCESSING: u32 = 0xC000_0016;
pub const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_NO_SUCH_FILE: u32 = 0xC000_000F;
pub const STATUS_END_OF_FILE: u32 = 0xC000_0011;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
pub const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
pub const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
pub const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
pub const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
pub const STATUS_BAD_NETWORK_NAME: u32 = 0xC000_00CC;

// Header flags
pub const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;

// CREATE dispositions
pub const FILE_SUPERSEDE: u32 = 0;
pub const FILE_OPEN: u32 = 1;
pub const FILE_CREATE: u32 = 2;
pub const FILE_OPEN_IF: u32 = 3;
pub const FILE_OVERWRITE: u32 = 4;
pub const FILE_OVERWRITE_IF: u32 = 5;

// CREATE access mask
pub const FILE_READ_DATA: u32 = 0x0000_0001;
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
pub const DELETE: u32 = 0x0001_0000;
pub const FILE_READ_EA: u32 = 0x0000_0008;
pub const FILE_WRITE_EA: u32 = 0x0000_0010;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

// File attributes
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub const FILE_ATTRIBUTE_HIDDEN: u32 = 0x0000_0002;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

// CREATE options
pub const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;

// Share access
pub const FILE_SHARE_READ: u32 = 0x0000_0001;
pub const FILE_SHARE_WRITE: u32 = 0x0000_0002;
pub const FILE_SHARE_DELETE: u32 = 0x0000_0004;

// QUERY_DIRECTORY info levels
pub const FILE_DIRECTORY_INFORMATION: u8 = 1;
pub const FILE_FULL_DIRECTORY_INFORMATION: u8 = 2;
pub const FILE_BOTH_DIRECTORY_INFORMATION: u8 = 3;
pub const FILE_ID_BOTH_DIRECTORY_INFORMATION: u8 = 37;
pub const FILE_ID_FULL_DIRECTORY_INFORMATION: u8 = 38;

// QUERY_INFO info types
pub const SMB2_0_INFO_FILE: u8 = 1;
pub const SMB2_0_INFO_FILESYSTEM: u8 = 2;
pub const SMB2_0_INFO_SECURITY: u8 = 3;

// File info classes
pub const FILE_BASIC_INFORMATION: u8 = 4;
pub const FILE_STANDARD_INFORMATION: u8 = 5;
pub const FILE_INTERNAL_INFORMATION: u8 = 6;
pub const FILE_EA_INFORMATION: u8 = 7;
pub const FILE_NETWORK_OPEN_INFORMATION: u8 = 34;
pub const FILE_ALL_INFORMATION: u8 = 18;
pub const FILE_STREAM_INFORMATION: u8 = 22;
pub const FILE_RENAME_INFORMATION: u8 = 10;
pub const FILE_DISPOSITION_INFORMATION: u8 = 13;
pub const FILE_POSITION_INFORMATION: u8 = 14;
pub const FILE_ATTRIBUTE_TAG_INFORMATION: u8 = 35;

// Filesystem info classes
pub const FS_SIZE_INFORMATION: u8 = 3;
pub const FS_ATTRIBUTE_INFORMATION: u8 = 5;
pub const FS_FULL_SIZE_INFORMATION: u8 = 7;
pub const FS_VOLUME_INFORMATION: u8 = 1;
pub const FS_SECTOR_SIZE_INFORMATION: u8 = 11;
