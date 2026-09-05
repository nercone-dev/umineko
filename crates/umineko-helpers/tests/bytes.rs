use umineko_helpers::{Buffer, BufferError, Bytes};

#[test]
fn bytes_hold_what_they_were_given() {
    assert!(Bytes::new().is_empty());
    assert_eq!(Bytes::new().len(), 0);
    let bytes = Bytes::copy_from_slice(b"hello world");
    assert_eq!(bytes.len(), 11);
    assert_eq!(bytes.as_slice(), b"hello world");
    assert_eq!(&bytes[..5], b"hello");
    assert_eq!(bytes.clone().into_vec(), b"hello world".to_vec());
}

#[test]
fn slices_share_the_storage_and_compare_by_content() {
    let bytes = Bytes::from(b"hello world".to_vec());
    let slice = bytes.slice(6, 5).unwrap();
    assert_eq!(slice.as_slice(), b"world");
    assert_eq!(slice, Bytes::copy_from_slice(b"world"));
    assert_eq!(slice.into_vec(), b"world".to_vec());
    assert_eq!(bytes.slice(6, 6), None);
    assert_eq!(bytes.slice(12, 0), None);
    assert_eq!(bytes.slice(11, 0).unwrap(), Bytes::new());
}

#[test]
fn a_split_covers_the_whole_of_the_original() {
    let bytes = Bytes::copy_from_slice(b"abcdef");
    let (left, right) = bytes.split(2).unwrap();
    assert_eq!(left.as_slice(), b"ab");
    assert_eq!(right.as_slice(), b"cdef");
    assert_eq!(bytes.split(0).unwrap().1, bytes);
    assert_eq!(bytes.split(6).unwrap().0, bytes);
    assert_eq!(bytes.split(7), None);
}

#[test]
fn a_buffer_gives_back_what_it_was_fed() {
    let mut buffer = Buffer::new();
    buffer.extend(b"hello ").unwrap();
    buffer.extend(b"world").unwrap();
    assert_eq!(buffer.len(), 11);
    assert_eq!(buffer.peek(5).unwrap(), b"hello");
    assert_eq!(buffer.consume(6).unwrap().as_slice(), b"hello ");
    assert_eq!(buffer.len(), 5);
    assert_eq!(buffer.consume(6), None);
    assert_eq!(buffer.consume(5).unwrap().as_slice(), b"world");
    assert!(buffer.is_empty());
}

#[test]
fn a_buffer_finds_and_drops_a_delimiter() {
    let mut buffer = Buffer::new();
    buffer.extend(b"GET / HTTP/1.1\r\nHost: example\r\n\r\n").unwrap();
    assert_eq!(buffer.find(b"\r\n"), Some(14));
    assert_eq!(buffer.consume_until(b"\r\n").unwrap().as_slice(), b"GET / HTTP/1.1");
    assert_eq!(buffer.consume_until(b"\r\n").unwrap().as_slice(), b"Host: example");
    assert_eq!(buffer.consume_until(b"\r\n").unwrap().as_slice(), b"");
    assert!(buffer.is_empty());
    assert_eq!(buffer.consume_until(b"\r\n"), None);
    assert_eq!(buffer.find(b""), None);
}

#[test]
fn a_limit_refuses_more_than_it_holds() {
    let mut buffer = Buffer::with_limit(8);
    assert_eq!(buffer.limit(), Some(8));
    buffer.extend(b"12345678").unwrap();
    assert_eq!(buffer.extend(b"9"), Err(BufferError::Overflow));
    assert_eq!(buffer.consume(4).unwrap().as_slice(), b"1234");
    buffer.extend(b"9012").unwrap();
    assert_eq!(buffer.as_slice(), b"56789012");
}

#[test]
fn compacting_and_clearing_keep_the_unread_bytes_right() {
    let mut buffer = Buffer::new();
    buffer.extend(b"abcdefgh").unwrap();
    buffer.consume(3);
    buffer.compact();
    assert_eq!(buffer.as_slice(), b"defgh");
    assert_eq!(buffer.advance(2), 2);
    assert_eq!(buffer.as_slice(), b"fgh");
    assert_eq!(buffer.advance(100), 3);
    assert!(buffer.is_empty());
    buffer.extend(b"xyz").unwrap();
    buffer.clear();
    assert!(buffer.is_empty());
}
