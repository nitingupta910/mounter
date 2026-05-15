use super::*;

#[test]
fn utf16le_roundtrip() {
    let s = "hello.txt";
    let encoded = to_utf16le(s);
    assert_eq!(encoded.len(), s.len() * 2);
    assert_eq!(from_utf16le(&encoded), s);
}

#[test]
fn filetime_roundtrip() {
    let secs = 1_700_000_000u64;
    let ft = unix_to_filetime(secs);
    assert_eq!(filetime_to_unix(ft), secs);
}

#[test]
fn filetime_epoch() {
    assert_eq!(unix_to_filetime(0), 116_444_736_000_000_000);
}

#[test]
fn read_u16_le_basic() {
    let buf = [0x34, 0x12, 0x00, 0x00];
    assert_eq!(read_u16_le(&buf, 0), 0x1234);
}

#[test]
fn is_smb1_detects_magic() {
    let mut msg = vec![0xff, b'S', b'M', b'B'];
    assert!(is_smb1_negotiate(&msg));
    msg[0] = 0xfe;
    assert!(!is_smb1_negotiate(&msg));
}
