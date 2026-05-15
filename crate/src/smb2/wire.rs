//! SMB2 wire-format helpers.

use std::io::{self, Read};

// ── Wire helpers ────────────────────────────────────────────────────

pub fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

pub fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

pub fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

pub fn read_message(stream: &mut dyn Read) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 16 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "bad SMB message length",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

/// Format a hex dump of the first `max_bytes` bytes of data (for debug logging).
pub fn hex_dump(data: &[u8], max_bytes: usize) -> String {
    use std::fmt::Write;
    let limit = data.len().min(max_bytes);
    let mut s = String::new();
    for (i, chunk) in data[..limit].chunks(16).enumerate() {
        let _ = write!(s, "\n  {:04x}: ", i * 16);
        for (j, byte) in chunk.iter().enumerate() {
            let _ = write!(s, "{:02x} ", byte);
            if j == 7 {
                s.push(' ');
            }
        }
        // Pad to align ASCII column
        let pad = 16 - chunk.len();
        for _ in 0..pad {
            s.push_str("   ");
        }
        if pad > 8 {
            s.push(' ');
        }
        s.push_str(" |");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                s.push(*byte as char);
            } else {
                s.push('.');
            }
        }
        s.push('|');
    }
    if data.len() > limit {
        let _ = write!(s, "\n  ... ({} more bytes)", data.len() - limit);
    }
    s
}

/// Encode a UTF-16LE string (for SMB wire format).
pub fn to_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

/// Decode a UTF-16LE string from SMB wire format.
pub fn from_utf16le(data: &[u8]) -> String {
    let chars: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&chars)
}

/// Windows FILETIME (100-ns intervals since 1601-01-01) from Unix timestamp.
pub fn unix_to_filetime(secs: u64) -> u64 {
    // Offset between 1601-01-01 and 1970-01-01 in 100-ns intervals
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    secs.saturating_mul(10_000_000).saturating_add(EPOCH_DIFF)
}

/// Unix timestamp from Windows FILETIME.
pub fn filetime_to_unix(ft: u64) -> u64 {
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    ft.saturating_sub(EPOCH_DIFF) / 10_000_000
}
