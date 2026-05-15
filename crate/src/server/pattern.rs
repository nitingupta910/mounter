//! SMB search patterns and macOS metadata filtering.

// ── macOS noise filter ──────────────────────────────────────────────
// Files that macOS queries for every directory but never exist on Linux.

/// Match an SMB search pattern against a filename.
/// Supports '*' (any chars), '?' (single char), and literal matches.
pub fn smb_pattern_match(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    // Case-insensitive comparison for exact match (SMB is case-insensitive)
    if !pattern.contains('*') && !pattern.contains('?') {
        return pattern.eq_ignore_ascii_case(name);
    }
    // Simple wildcard matching
    let p: Vec<char> = pattern.chars().collect();
    let n: Vec<char> = name.chars().collect();
    wildcard_match(&p, &n, 0, 0)
}

fn wildcard_match(p: &[char], n: &[char], pi: usize, ni: usize) -> bool {
    if pi == p.len() {
        return ni == n.len();
    }
    if p[pi] == '*' {
        // '*' matches zero or more characters
        for skip in 0..=n.len().saturating_sub(ni) {
            if wildcard_match(p, n, pi + 1, ni + skip) {
                return true;
            }
        }
        false
    } else if ni < n.len()
        && (p[pi] == '?' || p[pi].to_ascii_lowercase() == n[ni].to_ascii_lowercase())
    {
        wildcard_match(p, n, pi + 1, ni + 1)
    } else {
        false
    }
}

pub fn is_apple_metadata(name: &str) -> bool {
    name == ".DS_Store"
        || name == ".localized"
        || name == ".hidden"
        || name.starts_with("._")
        || name == "Icon\r"
        || name == ".Spotlight-V100"
        || name == ".Trashes"
        || name == ".fseventsd"
        || name == ".TemporaryItems"
        || name == ".com.apple.timemachine.donotpresent"
        || name == ".metadata_never_index"
        || name == ".metadata_never_index_unless_rootfs"
        || name == ".metadata_direct_scope_only"
        || name == "mdssvc"
        || name == "MsFteWds"
}

/// Files we fake as existing empty files in the share root so macOS
/// Spotlight skips indexing the entire volume.
pub(crate) fn is_spotlight_inhibitor(name: &str) -> bool {
    name == ".metadata_never_index"
}
