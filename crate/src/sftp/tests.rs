use super::protocol::*;
use super::session::{SftpSession, build_ssh_args, validate_ssh_target};
use super::types::FileAttr;
use super::wire::{Buf, Reader};
use std::io::Cursor;
use std::sync::Mutex;
use std::sync::atomic::AtomicU32;

fn session_with_packets(packets: &[(u8, u32, Vec<u8>)]) -> SftpSession {
    let mut bytes = Cursor::new(Vec::new());
    for (pkt_type, id, payload) in packets {
        SftpSession::write_packet(&mut bytes, *pkt_type, *id, payload).unwrap();
    }
    SftpSession {
        reader: Mutex::new(Box::new(Cursor::new(bytes.into_inner()))),
        writer: Mutex::new(Box::new(Cursor::new(Vec::<u8>::new()))),
        next_id: AtomicU32::new(1),
        _child: Mutex::new(None),
    }
}

fn data_packet(id: u32, data: &[u8]) -> (u8, u32, Vec<u8>) {
    let mut payload = Buf::new();
    payload.put_bytes(data);
    (SSH_FXP_DATA, id, payload.0)
}

fn status_packet(id: u32, code: u32) -> (u8, u32, Vec<u8>) {
    let mut payload = Buf::new();
    payload.put_u32(code);
    payload.put_str("");
    payload.put_str("");
    (SSH_FXP_STATUS, id, payload.0)
}

#[test]
fn buf_put_u32() {
    let mut buf = Buf::new();
    buf.put_u32(0x01020304);
    assert_eq!(buf.0, vec![0x01, 0x02, 0x03, 0x04]);
}

#[test]
fn buf_put_str() {
    let mut buf = Buf::new();
    buf.put_str("abc");
    // 4-byte length (3) + 3 bytes "abc"
    assert_eq!(buf.0, vec![0, 0, 0, 3, b'a', b'b', b'c']);
}

#[test]
fn buf_put_bytes() {
    let mut buf = Buf::new();
    buf.put_bytes(&[0xDE, 0xAD]);
    assert_eq!(buf.0, vec![0, 0, 0, 2, 0xDE, 0xAD]);
}

#[test]
fn buf_put_attrs() {
    let attrs = FileAttr {
        size: 1024,
        uid: 1000,
        gid: 1000,
        perm: 0o100644,
        atime: 1000000,
        mtime: 2000000,
    };
    let mut buf = Buf::new();
    buf.put_attrs(&attrs);

    let mut r = Reader::new(&buf.0);
    let flags = r.get_u32().unwrap();
    assert_eq!(
        flags,
        SSH_FILEXFER_ATTR_SIZE
            | SSH_FILEXFER_ATTR_UIDGID
            | SSH_FILEXFER_ATTR_PERMISSIONS
            | SSH_FILEXFER_ATTR_ACMODTIME
    );
    assert_eq!(r.get_u64().unwrap(), 1024);
    assert_eq!(r.get_u32().unwrap(), 1000); // uid
    assert_eq!(r.get_u32().unwrap(), 1000); // gid
    assert_eq!(r.get_u32().unwrap(), 0o100644); // perm
    assert_eq!(r.get_u32().unwrap(), 1000000); // atime
    assert_eq!(r.get_u32().unwrap(), 2000000); // mtime
}

#[test]
fn reader_get_u32() {
    let data = [0x00, 0x00, 0x01, 0x00];
    let mut r = Reader::new(&data);
    assert_eq!(r.get_u32().unwrap(), 256);
}

#[test]
fn reader_get_string() {
    let mut buf = Buf::new();
    buf.put_str("hello");
    let mut r = Reader::new(&buf.0);
    assert_eq!(r.get_string().unwrap(), "hello");
}

#[test]
fn reader_get_attrs_roundtrip() {
    let original = FileAttr {
        size: 999,
        uid: 501,
        gid: 20,
        perm: 0o40755,
        atime: 12345,
        mtime: 67890,
    };
    let mut buf = Buf::new();
    buf.put_attrs(&original);

    let mut r = Reader::new(&buf.0);
    let parsed = r.get_attrs().unwrap();
    assert_eq!(parsed.size, original.size);
    assert_eq!(parsed.uid, original.uid);
    assert_eq!(parsed.gid, original.gid);
    assert_eq!(parsed.perm, original.perm);
    assert_eq!(parsed.atime, original.atime);
    assert_eq!(parsed.mtime, original.mtime);
}

#[test]
fn reader_underflow() {
    let data = [0x00, 0x01];
    let mut r = Reader::new(&data);
    assert!(r.get_u32().is_err());
}

#[test]
fn open_flags_rdonly() {
    let sf = SftpSession::open_flags_from_libc(libc::O_RDONLY);
    assert_eq!(sf, SSH_FXF_READ);
}

#[test]
fn open_flags_wronly() {
    let sf = SftpSession::open_flags_from_libc(libc::O_WRONLY);
    assert_eq!(sf, SSH_FXF_WRITE);
}

#[test]
fn open_flags_rdwr() {
    let sf = SftpSession::open_flags_from_libc(libc::O_RDWR);
    assert_eq!(sf, SSH_FXF_READ | SSH_FXF_WRITE);
}

#[test]
fn open_flags_create_trunc() {
    let sf = SftpSession::open_flags_from_libc(libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC);
    assert!(sf & SSH_FXF_WRITE != 0);
    assert!(sf & SSH_FXF_CREAT != 0);
    assert!(sf & SSH_FXF_TRUNC != 0);
}

#[test]
fn open_flags_append() {
    let sf = SftpSession::open_flags_from_libc(libc::O_WRONLY | libc::O_APPEND);
    assert!(sf & SSH_FXF_WRITE != 0);
    assert!(sf & SSH_FXF_APPEND != 0);
}

#[test]
fn open_flags_excl() {
    let sf = SftpSession::open_flags_from_libc(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL);
    assert!(sf & SSH_FXF_WRITE != 0);
    assert!(sf & SSH_FXF_CREAT != 0);
    assert!(sf & SSH_FXF_EXCL != 0);
}

#[test]
fn ssh_args_default_do_not_accept_new_host_keys() {
    let args = build_ssh_args("example.com", 22, Some("alice"), None, false).unwrap();
    assert!(
        !args
            .iter()
            .any(|a| a == "-oStrictHostKeyChecking=accept-new")
    );
    assert!(args.contains(&"-oBatchMode=yes".to_string()));
    assert!(args.contains(&"-oServerAliveInterval=15".to_string()));
    assert!(args.contains(&"-oServerAliveCountMax=3".to_string()));
    assert!(
        args.windows(3)
            .any(|w| w[0] == "--" && w[1] == "alice@example.com" && w[2] == "sftp")
    );
    assert_eq!(args[args.len() - 3], "--");
    assert_eq!(args[args.len() - 2], "alice@example.com");
    assert_eq!(args[args.len() - 1], "sftp");
}

#[test]
fn ssh_args_accept_new_host_key_is_explicit() {
    let args = build_ssh_args("example.com", 2222, None, Some("/tmp/id"), true).unwrap();
    assert!(
        args.iter()
            .any(|a| a == "-oStrictHostKeyChecking=accept-new")
    );
    assert!(args.windows(2).any(|w| w == ["-p", "2222"]));
    assert!(args.windows(2).any(|w| w == ["-i", "/tmp/id"]));
    assert!(
        args.windows(3)
            .any(|w| w[0] == "--" && w[1] == "example.com" && w[2] == "sftp")
    );
}

#[test]
fn ssh_target_validation_rejects_option_like_values() {
    assert!(validate_ssh_target(None, "-oProxyCommand=bad").is_err());
    assert!(validate_ssh_target(Some("user"), "-badhost").is_err());
    assert!(validate_ssh_target(Some("-baduser"), "example.com").is_err());
    assert!(validate_ssh_target(None, "").is_err());
    assert!(validate_ssh_target(Some("user\nname"), "example.com").is_err());
    assert!(validate_ssh_target(Some("user"), "example-host").is_ok());
}

#[test]
fn large_read_reorders_out_of_order_responses() {
    let first = vec![b'a'; MAX_READ_SIZE as usize];
    let second = b"second".to_vec();
    let mut expected = first.clone();
    expected.extend_from_slice(&second);
    let session = session_with_packets(&[data_packet(2, &second), data_packet(1, &first)]);

    let data = session
        .read(b"handle", 0, MAX_READ_SIZE + second.len() as u32)
        .unwrap();
    assert_eq!(data, expected);
}

#[test]
fn large_read_handles_short_chunks_without_skipping_bytes() {
    let chunk = 65536usize;
    let tail = b"tail".to_vec();
    let a = vec![b'a'; chunk];
    let b = vec![b'b'; chunk];
    let c = vec![b'c'; chunk];
    let d = vec![b'd'; chunk];
    let mut expected = a.clone();
    expected.extend_from_slice(&b);
    expected.extend_from_slice(&c);
    expected.extend_from_slice(&d);
    expected.extend_from_slice(&tail);
    let session = session_with_packets(&[
        data_packet(2, b"ignored"),
        data_packet(1, &a),
        data_packet(5, &d),
        data_packet(3, &b),
        data_packet(6, &tail),
        data_packet(4, &c),
        status_packet(7, SSH_FX_EOF),
    ]);

    let data = session
        .read(b"handle", 0, MAX_READ_SIZE + tail.len() as u32 + 1)
        .unwrap();
    assert_eq!(data, expected);
}
