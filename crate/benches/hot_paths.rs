//! Benchmarks for the SMB server hot paths.
//!
//! These cover the functions that run on every SMB request — pattern matching,
//! cache lookups, directory entry serialization, and wire-format helpers.
//!
//! Run with: cargo bench

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use mounter::server::{AttrCache, DirCache, is_apple_metadata, smb_pattern_match};
use mounter::sftp::{DirEntry, FileAttr};
use mounter::smb2::{filetime_to_unix, from_utf16le, to_utf16le, unix_to_filetime};

fn make_attr(size: u64, perm: u32) -> FileAttr {
    FileAttr {
        size,
        uid: 1000,
        gid: 1000,
        perm,
        atime: 1700000000,
        mtime: 1700000000,
    }
}

fn make_dir_entries(n: usize) -> Vec<DirEntry> {
    (0..n)
        .map(|i| DirEntry {
            name: format!("file_{i:04}.txt"),
            attrs: make_attr(i as u64 * 1000, if i % 5 == 0 { 0o40755 } else { 0o100644 }),
        })
        .collect()
}

// ── Pattern matching ────────────────────────────────────────────────

fn bench_pattern_match(c: &mut Criterion) {
    let mut g = c.benchmark_group("pattern_match");

    // The most common case: macOS sends exact filename lookups
    g.bench_function("exact_hit", |b| {
        b.iter(|| smb_pattern_match(black_box(".bashrc"), black_box(".bashrc")))
    });
    g.bench_function("exact_miss", |b| {
        b.iter(|| smb_pattern_match(black_box(".bashrc"), black_box(".gitconfig")))
    });
    g.bench_function("exact_case_insensitive", |b| {
        b.iter(|| smb_pattern_match(black_box("README.MD"), black_box("readme.md")))
    });
    // Wildcard — used for full directory listings
    g.bench_function("wildcard_star", |b| {
        b.iter(|| smb_pattern_match(black_box("*"), black_box("some_file.txt")))
    });
    g.bench_function("glob_star_dot_txt", |b| {
        b.iter(|| smb_pattern_match(black_box("*.txt"), black_box("readme.txt")))
    });
    g.bench_function("glob_star_dot_txt_miss", |b| {
        b.iter(|| smb_pattern_match(black_box("*.txt"), black_box("readme.md")))
    });

    g.finish();
}

// ── Apple metadata filter ───────────────────────────────────────────

fn bench_apple_metadata(c: &mut Criterion) {
    let mut g = c.benchmark_group("apple_metadata");

    g.bench_function("positive_ds_store", |b| {
        b.iter(|| is_apple_metadata(black_box(".DS_Store")))
    });
    g.bench_function("positive_dot_underscore", |b| {
        b.iter(|| is_apple_metadata(black_box("._somefile")))
    });
    g.bench_function("negative_regular", |b| {
        b.iter(|| is_apple_metadata(black_box("readme.md")))
    });

    g.finish();
}

// ── AttrCache ───────────────────────────────────────────────────────

fn bench_attr_cache(c: &mut Criterion) {
    let mut g = c.benchmark_group("attr_cache");

    // Populate a cache with realistic number of entries
    let mut cache = AttrCache::new();
    for i in 0..500 {
        cache.insert(
            format!("/home/user/dir/file_{i:04}.txt"),
            make_attr(i * 100, 0o100644),
            false,
        );
    }
    for i in 0..100 {
        cache.insert_negative(format!("/home/user/dir/._{i:04}"));
    }

    g.bench_function("get_hit", |b| {
        b.iter(|| cache.get(black_box("/home/user/dir/file_0250.txt")))
    });
    g.bench_function("get_miss", |b| {
        b.iter(|| cache.get(black_box("/home/user/dir/nonexistent.txt")))
    });
    g.bench_function("is_negative_hit", |b| {
        b.iter(|| cache.is_negative(black_box("/home/user/dir/._0050")))
    });
    g.bench_function("is_negative_miss", |b| {
        b.iter(|| cache.is_negative(black_box("/home/user/dir/realfile.txt")))
    });

    g.bench_function("insert", |b| {
        let mut c = AttrCache::new();
        let attr = make_attr(1024, 0o100644);
        b.iter(|| c.insert(black_box("/a/b/c".into()), attr.clone(), false))
    });

    g.finish();
}

// ── DirCache ────────────────────────────────────────────────────────

fn bench_dir_cache(c: &mut Criterion) {
    let mut g = c.benchmark_group("dir_cache");

    let mut cache = DirCache::new();
    cache.insert("/home/user/small".into(), make_dir_entries(20));
    cache.insert("/home/user/large".into(), make_dir_entries(500));

    // get() returns Arc — should be very cheap (no clone of entries)
    g.bench_function("get_small_dir", |b| {
        b.iter(|| cache.get(black_box("/home/user/small")))
    });
    g.bench_function("get_large_dir", |b| {
        b.iter(|| cache.get(black_box("/home/user/large")))
    });
    g.bench_function("get_miss", |b| {
        b.iter(|| cache.get(black_box("/home/user/nope")))
    });

    g.finish();
}

// ── Cache eviction ──────────────────────────────────────────────────

fn bench_eviction(c: &mut Criterion) {
    let mut g = c.benchmark_group("eviction");

    g.bench_function("attr_cache_500_entries", |b| {
        b.iter_batched(
            || {
                let mut c = AttrCache::new();
                for i in 0..500 {
                    c.insert(format!("/p/{i}"), make_attr(i, 0o100644), false);
                }
                c
            },
            |mut c| c.evict_expired(),
            criterion::BatchSize::SmallInput,
        )
    });

    g.bench_function("dir_cache_50_dirs", |b| {
        b.iter_batched(
            || {
                let mut c = DirCache::new();
                for i in 0..50 {
                    c.insert(format!("/d/{i}"), make_dir_entries(20));
                }
                c
            },
            |mut c| c.evict_expired(),
            criterion::BatchSize::SmallInput,
        )
    });

    g.finish();
}

// ── insert_dir_entries (populates attr cache from readdir) ──────────

fn bench_insert_dir_entries(c: &mut Criterion) {
    let entries = make_dir_entries(100);

    c.bench_function("insert_dir_entries_100", |b| {
        let mut cache = AttrCache::new();
        b.iter(|| {
            cache.insert_dir_entries(black_box("/home/user/dir"), black_box(&entries));
        })
    });
}

// ── Wire format helpers ─────────────────────────────────────────────

fn bench_wire_format(c: &mut Criterion) {
    let mut g = c.benchmark_group("wire_format");

    g.bench_function("to_utf16le_short", |b| {
        b.iter(|| to_utf16le(black_box("readme.txt")))
    });
    g.bench_function("to_utf16le_long", |b| {
        b.iter(|| {
            to_utf16le(black_box(
                "this_is_a_very_long_filename_with_many_characters.tar.gz",
            ))
        })
    });

    let encoded = to_utf16le("readme.txt");
    g.bench_function("from_utf16le", |b| {
        b.iter(|| from_utf16le(black_box(&encoded)))
    });

    g.bench_function("unix_to_filetime", |b| {
        b.iter(|| unix_to_filetime(black_box(1700000000)))
    });
    g.bench_function("filetime_to_unix", |b| {
        b.iter(|| filetime_to_unix(black_box(133_444_736_000_000_000)))
    });

    g.finish();
}

// ── Simulated QUERY_DIRECTORY pattern scan ──────────────────────────

fn bench_dir_scan(c: &mut Criterion) {
    let entries = make_dir_entries(200);

    let mut g = c.benchmark_group("dir_scan");

    // Simulates what QUERY_DIRECTORY does: filter entries by pattern
    g.bench_function("wildcard_200_entries", |b| {
        b.iter(|| {
            let _: Vec<_> = entries
                .iter()
                .filter(|e| smb_pattern_match(black_box("*"), &e.name))
                .collect();
        })
    });

    g.bench_with_input(
        BenchmarkId::new("exact_in_200", "file_0100.txt"),
        &"file_0100.txt",
        |b, pat| {
            b.iter(|| {
                let _: Vec<_> = entries
                    .iter()
                    .filter(|e| smb_pattern_match(black_box(pat), &e.name))
                    .collect();
            })
        },
    );

    g.bench_with_input(
        BenchmarkId::new("exact_miss_in_200", "nonexistent.txt"),
        &"nonexistent.txt",
        |b, pat| {
            b.iter(|| {
                let _: Vec<_> = entries
                    .iter()
                    .filter(|e| smb_pattern_match(black_box(pat), &e.name))
                    .collect();
            })
        },
    );

    g.finish();
}

criterion_group!(
    benches,
    bench_pattern_match,
    bench_apple_metadata,
    bench_attr_cache,
    bench_dir_cache,
    bench_eviction,
    bench_insert_dir_entries,
    bench_wire_format,
    bench_dir_scan,
);
criterion_main!(benches);
