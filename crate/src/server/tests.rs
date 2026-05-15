use super::cache::{CachedAttr, CachedDir};
use super::types::ReadAhead;
use super::*;
use crate::sftp::ReconnectingSftp;
use crate::sftp::{DirEntry, FileAttr};
use std::sync::Arc;
use std::time::{Duration, Instant};

// ── smb_pattern_match ──────────────────────────────────────────

#[test]
fn pattern_wildcard_matches_everything() {
    assert!(smb_pattern_match("*", "anything"));
    assert!(smb_pattern_match("*", ""));
    assert!(smb_pattern_match("*", ".DS_Store"));
}

#[test]
fn pattern_exact_case_insensitive() {
    assert!(smb_pattern_match("hello.txt", "hello.txt"));
    assert!(smb_pattern_match("Hello.TXT", "hello.txt"));
    assert!(smb_pattern_match("hello.txt", "HELLO.TXT"));
    assert!(!smb_pattern_match("hello.txt", "hello.tx"));
    assert!(!smb_pattern_match("hello.txt", "hello.txtt"));
}

#[test]
fn pattern_question_mark() {
    assert!(smb_pattern_match("?.txt", "a.txt"));
    assert!(!smb_pattern_match("?.txt", "ab.txt"));
    assert!(smb_pattern_match("he??o", "hello"));
    assert!(!smb_pattern_match("he??o", "helo"));
}

#[test]
fn pattern_star_prefix_suffix() {
    assert!(smb_pattern_match("*.txt", "readme.txt"));
    assert!(smb_pattern_match("*.txt", ".txt"));
    assert!(!smb_pattern_match("*.txt", "readme.md"));
    assert!(smb_pattern_match("readme.*", "readme.txt"));
    assert!(smb_pattern_match("readme.*", "readme."));
}

#[test]
fn pattern_star_middle() {
    assert!(smb_pattern_match("a*z", "az"));
    assert!(smb_pattern_match("a*z", "abcz"));
    assert!(!smb_pattern_match("a*z", "abcx"));
}

#[test]
fn pattern_empty_inputs() {
    assert!(smb_pattern_match("*", ""));
    assert!(!smb_pattern_match("a", ""));
    assert!(!smb_pattern_match("", "a"));
    assert!(smb_pattern_match("", ""));
}

#[test]
fn pattern_no_panic_on_long_star() {
    // Regression: wildcard_match used n.len() - ni which could underflow
    assert!(smb_pattern_match("*", "x"));
    assert!(!smb_pattern_match("a*b*c", "ac"));
    assert!(smb_pattern_match("a*b*c", "abc"));
    assert!(smb_pattern_match("a*b*c", "aXXbYYc"));
}

// ── is_apple_metadata ──────────────────────────────────────────

#[test]
fn apple_metadata_detected() {
    assert!(is_apple_metadata(".DS_Store"));
    assert!(is_apple_metadata("._somefile"));
    assert!(is_apple_metadata(".Spotlight-V100"));
    assert!(is_apple_metadata(".Trashes"));
    assert!(is_apple_metadata(".fseventsd"));
    assert!(is_apple_metadata("Icon\r"));
}

#[test]
fn non_apple_metadata() {
    assert!(!is_apple_metadata("readme.md"));
    assert!(!is_apple_metadata(".gitignore"));
    assert!(!is_apple_metadata(".bashrc"));
    assert!(!is_apple_metadata("DS_Store")); // no leading dot
}

// ── AttrCache ──────────────────────────────────────────────────

fn test_attr(size: u64, perm: u32) -> FileAttr {
    FileAttr {
        size,
        uid: 1000,
        gid: 1000,
        perm,
        atime: 1000,
        mtime: 2000,
    }
}

#[test]
fn attr_cache_insert_and_get() {
    let mut c = AttrCache::new();
    c.insert("/a/b".into(), test_attr(100, 0o100644), false);
    let (attr, is_dir) = c.get("/a/b").unwrap();
    assert_eq!(attr.size, 100);
    assert!(!is_dir);
}

#[test]
fn attr_cache_miss() {
    let c = AttrCache::new();
    assert!(c.get("/nonexistent").is_none());
}

#[test]
fn attr_cache_negative() {
    let mut c = AttrCache::new();
    assert!(!c.is_negative("/a"));
    c.insert_negative("/a".into());
    assert!(c.is_negative("/a"));
}

#[test]
fn attr_cache_insert_clears_negative() {
    let mut c = AttrCache::new();
    c.insert_negative("/a".into());
    assert!(c.is_negative("/a"));
    c.insert("/a".into(), test_attr(10, 0o100644), false);
    assert!(!c.is_negative("/a"));
    assert!(c.get("/a").is_some());
}

#[test]
fn attr_cache_invalidate() {
    let mut c = AttrCache::new();
    c.insert("/a".into(), test_attr(10, 0o100644), false);
    c.insert_negative("/b".into());
    c.invalidate("/a");
    c.invalidate("/b");
    assert!(c.get("/a").is_none());
    assert!(!c.is_negative("/b"));
}

#[test]
fn attr_cache_insert_dir_entries() {
    let mut c = AttrCache::new();
    let entries = vec![
        DirEntry {
            name: "file.txt".into(),
            attrs: test_attr(500, 0o100644),
        },
        DirEntry {
            name: "subdir".into(),
            attrs: test_attr(4096, 0o40755),
        },
    ];
    c.insert_dir_entries("/home", &entries);
    let (a, d) = c.get("/home/file.txt").unwrap();
    assert_eq!(a.size, 500);
    assert!(!d);
    let (a, d) = c.get("/home/subdir").unwrap();
    assert_eq!(a.size, 4096);
    assert!(d);
}

#[test]
fn attr_cache_evict_expired() {
    let mut c = AttrCache::new();
    // Insert with a very short TTL by directly manipulating
    c.positive.insert(
        "/stale".into(),
        CachedAttr {
            attr: test_attr(1, 0o100644),
            is_dir: false,
            expires: Instant::now() - Duration::from_secs(1),
        },
    );
    c.negative
        .insert("/gone".into(), Instant::now() - Duration::from_secs(1));
    c.insert("/fresh".into(), test_attr(2, 0o100644), false);

    assert_eq!(c.positive.len(), 2);
    assert_eq!(c.negative.len(), 1);
    c.evict_expired();
    assert_eq!(c.positive.len(), 1); // only /fresh remains
    assert_eq!(c.negative.len(), 0);
    assert!(c.get("/fresh").is_some());
}

// ── DirCache ───────────────────────────────────────────────────

#[test]
fn dir_cache_insert_and_get() {
    let mut c = DirCache::new();
    let entries = vec![DirEntry {
        name: "a.txt".into(),
        attrs: test_attr(10, 0o100644),
    }];
    c.insert("/dir".into(), entries);
    let got = c.get("/dir").unwrap();
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].name, "a.txt");
}

#[test]
fn dir_cache_miss() {
    let c = DirCache::new();
    assert!(c.get("/nope").is_none());
}

#[test]
fn dir_cache_expired_is_miss() {
    let mut c = DirCache::new();
    c.dirs.insert(
        "/old".into(),
        CachedDir {
            entries: Arc::new(vec![]),
            expires: Instant::now() - Duration::from_secs(1),
        },
    );
    assert!(c.get("/old").is_none());
}

#[test]
fn dir_cache_invalidate() {
    let mut c = DirCache::new();
    c.insert("/dir".into(), vec![]);
    assert!(c.get("/dir").is_some());
    c.invalidate("/dir");
    assert!(c.get("/dir").is_none());
}

#[test]
fn dir_cache_arc_sharing() {
    let mut c = DirCache::new();
    let entries = vec![DirEntry {
        name: "x".into(),
        attrs: test_attr(1, 0o100644),
    }];
    c.insert("/d".into(), entries);
    let a1 = c.get("/d").unwrap();
    let a2 = c.get("/d").unwrap();
    // Both point to the same allocation
    assert!(Arc::ptr_eq(&a1, &a2));
}

#[test]
fn dir_cache_evict_expired() {
    let mut c = DirCache::new();
    c.dirs.insert(
        "/stale".into(),
        CachedDir {
            entries: Arc::new(vec![]),
            expires: Instant::now() - Duration::from_secs(1),
        },
    );
    c.insert("/fresh".into(), vec![]);
    assert_eq!(c.dirs.len(), 2);
    c.evict_expired();
    assert_eq!(c.dirs.len(), 1);
    assert!(c.get("/fresh").is_some());
}

// ── ReadAhead ──────────────────────────────────────────────────

#[test]
fn readahead_hit_within_buffer() {
    let ra = ReadAhead {
        data: vec![0u8; 512 * 1024], // 512KB
        offset: 1000,
    };
    // Read at offset 2000, length 100 — within buffer
    let off = 2000u64;
    let len = 100u64;
    assert!(off >= ra.offset && off + len <= ra.offset + ra.data.len() as u64);
    let start = (off - ra.offset) as usize;
    assert_eq!(start, 1000);
}

#[test]
fn readahead_miss_before_buffer() {
    let ra = ReadAhead {
        data: vec![0u8; 1024],
        offset: 5000,
    };
    let off = 4000u64;
    let len = 100u64;
    assert!(!(off >= ra.offset && off + len <= ra.offset + ra.data.len() as u64));
}

#[test]
fn readahead_miss_past_buffer() {
    let ra = ReadAhead {
        data: vec![0u8; 1024],
        offset: 0,
    };
    let off = 500u64;
    let len = 1000u64;
    // off + len = 1500 > 0 + 1024
    assert!(!(off >= ra.offset && off + len <= ra.offset + ra.data.len() as u64));
}

// ── full_path / invalidate_path ────────────────────────────────

#[test]
fn full_path_empty_returns_root() {
    let sess = make_test_session();
    assert_eq!(sess.full_path("").unwrap(), "/home/user");
    assert_eq!(sess.full_path("\\").unwrap(), "/home/user");
    assert_eq!(sess.full_path("/").unwrap(), "/home/user");
}

#[test]
fn full_path_relative() {
    let sess = make_test_session();
    assert_eq!(
        sess.full_path("docs/readme.md").unwrap(),
        "/home/user/docs/readme.md"
    );
}

#[test]
fn full_path_backslash_normalized() {
    let sess = make_test_session();
    assert_eq!(
        sess.full_path("docs\\sub\\file.txt").unwrap(),
        "/home/user/docs/sub/file.txt"
    );
}

#[test]
fn full_path_rejects_unsafe_paths() {
    let sess = make_test_session();
    for path in [
        "..\\outside.txt",
        "../outside.txt",
        "dir/../../outside.txt",
        "/absolute",
        "dir//file",
        "dir/./file",
        "dir/\n/file",
    ] {
        assert!(sess.full_path(path).is_err(), "{path} should be rejected");
    }
}

#[test]
fn invalidate_path_clears_both_caches() {
    let mut sess = make_test_session();
    // Populate attr cache
    sess.cache.insert(
        "/home/user/dir/file.txt".into(),
        test_attr(10, 0o100644),
        false,
    );
    // Populate dir cache for parent
    sess.dir_cache.insert(
        "/home/user/dir".into(),
        vec![DirEntry {
            name: "file.txt".into(),
            attrs: test_attr(10, 0o100644),
        }],
    );
    assert!(sess.cache.get("/home/user/dir/file.txt").is_some());
    assert!(sess.dir_cache.get("/home/user/dir").is_some());

    sess.invalidate_path("/home/user/dir/file.txt");
    assert!(sess.cache.get("/home/user/dir/file.txt").is_none());
    assert!(sess.dir_cache.get("/home/user/dir").is_none());
}

// ── Helper: create a minimal SmbSession for testing ────────────

fn make_test_session() -> SmbSession {
    let sftp = Arc::new(ReconnectingSftp::dummy());
    SmbSession::new(
        sftp,
        "/home/user".into(),
        "test".into(),
        "mounter-test".into(),
    )
}
