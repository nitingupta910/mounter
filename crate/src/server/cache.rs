//! Attribute and directory listing caches.

use super::pattern::is_apple_metadata;
use crate::sftp::{DirEntry, FileAttr};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ── Attr cache ──────────────────────────────────────────────────────

const CACHE_TTL_SECS: u64 = 30;
const NEG_CACHE_TTL_SECS: u64 = 60; // longer for negative since Apple metadata never exists

pub struct CachedAttr {
    pub(crate) attr: FileAttr,
    pub(crate) is_dir: bool,
    pub(crate) expires: Instant,
}

pub struct AttrCache {
    pub(crate) positive: HashMap<String, CachedAttr>,
    pub(crate) negative: HashMap<String, Instant>,
}

impl AttrCache {
    pub fn new() -> Self {
        AttrCache {
            positive: HashMap::new(),
            negative: HashMap::new(),
        }
    }

    pub fn get(&self, path: &str) -> Option<(&FileAttr, bool)> {
        self.positive.get(path).and_then(|c| {
            if c.expires > Instant::now() {
                Some((&c.attr, c.is_dir))
            } else {
                None
            }
        })
    }

    pub fn is_negative(&self, path: &str) -> bool {
        self.negative
            .get(path)
            .map(|exp| *exp > Instant::now())
            .unwrap_or(false)
    }

    pub fn insert(&mut self, path: String, attr: FileAttr, is_dir: bool) {
        self.negative.remove(&path);
        self.positive.insert(
            path,
            CachedAttr {
                attr,
                is_dir,
                expires: Instant::now() + std::time::Duration::from_secs(CACHE_TTL_SECS),
            },
        );
    }

    pub fn insert_negative(&mut self, path: String) {
        let ttl = if is_apple_metadata(path.rsplit('/').next().unwrap_or("")) {
            NEG_CACHE_TTL_SECS
        } else {
            CACHE_TTL_SECS / 2
        };
        self.negative
            .insert(path, Instant::now() + std::time::Duration::from_secs(ttl));
    }

    pub fn invalidate(&mut self, path: &str) {
        self.positive.remove(path);
        self.negative.remove(path);
    }

    /// Remove expired entries periodically to prevent unbounded growth.
    pub fn evict_expired(&mut self) {
        let now = Instant::now();
        self.positive.retain(|_, c| c.expires > now);
        self.negative.retain(|_, exp| *exp > now);
    }

    pub fn insert_dir_entries(&mut self, parent: &str, entries: &[DirEntry]) {
        for e in entries {
            let child = format!("{parent}/{}", e.name);
            let is_dir = e.attrs.perm & 0o40000 != 0;
            self.insert(child, e.attrs.clone(), is_dir);
        }
    }
}

// ── Directory listing cache (session-level) ─────────────────────────
// macOS sends per-file CREATE+QUERY_DIRECTORY+CLOSE compounds for stat
// lookups.  Without this cache, each compound triggers a full SFTP readdir.

const DIR_CACHE_TTL_SECS: u64 = 15;

pub struct CachedDir {
    pub(crate) entries: Arc<Vec<DirEntry>>,
    pub(crate) expires: Instant,
}

pub struct DirCache {
    pub(crate) dirs: HashMap<String, CachedDir>,
}

impl DirCache {
    pub fn new() -> Self {
        DirCache {
            dirs: HashMap::new(),
        }
    }

    pub fn get(&self, path: &str) -> Option<Arc<Vec<DirEntry>>> {
        self.dirs.get(path).and_then(|c| {
            if c.expires > Instant::now() {
                Some(Arc::clone(&c.entries))
            } else {
                None
            }
        })
    }

    pub fn insert(&mut self, path: String, entries: Vec<DirEntry>) {
        self.dirs.insert(
            path,
            CachedDir {
                entries: Arc::new(entries),
                expires: Instant::now() + Duration::from_secs(DIR_CACHE_TTL_SECS),
            },
        );
    }

    pub fn invalidate(&mut self, path: &str) {
        self.dirs.remove(path);
    }

    pub fn evict_expired(&mut self) {
        let now = Instant::now();
        self.dirs.retain(|_, c| c.expires > now);
    }
}
