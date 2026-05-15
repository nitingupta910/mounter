//! Per-open SMB handle state.

use crate::sftp::DirEntry;
use std::sync::Arc;

// ── Open file/dir handles ───────────────────────────────────────────

/// Read cache: cache each SFTP read so small follow-up reads (macOS
/// sends 2KB resource-fork probes after each 512KB read) are served
/// without an extra SFTP round-trip.

pub(crate) struct ReadAhead {
    pub(crate) data: Vec<u8>,
    pub(crate) offset: u64, // start offset of buffered data
}

pub(crate) struct OpenHandle {
    pub(crate) sftp_handle: Option<Vec<u8>>, // None for directories
    pub(crate) path: String,
    pub(crate) is_dir: bool,
    pub(crate) is_pipe: bool,
    pub(crate) pipe_response: Option<Vec<u8>>, // buffered DCE/RPC response for named pipes
    pub(crate) dir_entries: Option<Arc<Vec<DirEntry>>>, // shared with dir_cache
    pub(crate) dir_offset: usize,
    pub(crate) readahead: Option<ReadAhead>,
}
