use umineko_codec_gzip::{Gzip, GzipError, GzipHeader};

fn text(length: usize) -> Vec<u8> {
    let words = ["alpha ", "beta ", "gamma ", "delta ", "alpha ", "beta "];
    let mut data = Vec::new();
    while data.len() < length {
        data.extend_from_slice(words[data.len() % words.len()].as_bytes());
    }
    data.truncate(length);
    data
}

/// `empty`, as gzip writes it.
const EMPTY: [u8; 20] = [
    0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

/// `short`, as gzip writes it.
const SHORT: [u8; 31] = [
    0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF, 0xCB, 0x48, 0xCD, 0xC9, 0xC9, 0x57,
    0x28, 0xCF, 0x2F, 0xCA, 0x49, 0x01, 0x00, 0x85, 0x11, 0x4A, 0x0D, 0x0B, 0x00, 0x00, 0x00,
];

/// `text`, as gzip writes it.
const TEXT: [u8; 72] = [
    0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF, 0xED, 0xC4, 0x21, 0x01, 0x00, 0x00,
    0x08, 0x03, 0xB0, 0x2A, 0x54, 0xBB, 0x43, 0x20, 0xE8, 0xAF, 0x88, 0x81, 0xD9, 0xC4, 0x32, 0xDB,
    0xA9, 0xD8, 0xB6, 0x6D, 0xDB, 0xB6, 0x6D, 0xDB, 0xB6, 0x6D, 0xDB, 0xB6, 0x6D, 0xDB, 0xB6, 0x6D,
    0xDB, 0xB6, 0x6D, 0xDB, 0xB6, 0x6D, 0xDB, 0xB6, 0x6D, 0xDB, 0xB6, 0x6D, 0xDB, 0xB6, 0x9F, 0x3F,
    0x25, 0xA6, 0x98, 0x67, 0x20, 0x4E, 0x00, 0x00,
];

/// A member that carries a name and a modification time.
const NAMED: [u8; 38] = [
    0x1F, 0x8B, 0x08, 0x08, 0x00, 0xF1, 0x53, 0x65, 0x02, 0xFF, 0x72, 0x65, 0x70, 0x6F, 0x72, 0x74,
    0x2E, 0x74, 0x78, 0x74, 0x00, 0x2B, 0x48, 0xAC, 0xCC, 0xC9, 0x4F, 0x4C, 0x01, 0x00, 0x15, 0x6A,
    0x2C, 0x42, 0x07, 0x00, 0x00, 0x00,
];

/// Two members, one after the other.
const PAIR: [u8; 52] = [
    0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xFF, 0x4B, 0xCB, 0x2C, 0x2A, 0x2E, 0x51,
    0x00, 0x00, 0xFC, 0x7A, 0xF1, 0x1C, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x8B, 0x08, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x02, 0xFF, 0x2B, 0x4E, 0x4D, 0xCE, 0xCF, 0x4B, 0x01, 0x00, 0x69, 0x11, 0x1F, 0xB6,
    0x06, 0x00, 0x00, 0x00,
];

#[test]
fn reads_members_gzip_wrote() {
    let codec = Gzip::default();
    assert_eq!(codec.decode(&EMPTY).unwrap(), b"");
    assert_eq!(codec.decode(&SHORT).unwrap(), b"hello world");
    assert_eq!(codec.decode(&TEXT).unwrap(), text(20000));
    assert_eq!(codec.decode(&PAIR).unwrap(), b"first second");
}

#[test]
fn reads_the_optional_header_fields() {
    let (header, length) = GzipHeader::decode(&NAMED).unwrap();
    assert_eq!(header.name.as_deref(), Some("report.txt"));
    assert_eq!(header.modified, Some(1700000000));
    assert_eq!(length, 10 + "report.txt".len() + 1);
    assert_eq!(Gzip::default().decode(&NAMED).unwrap(), b"payload");
}

#[test]
fn writes_the_optional_header_fields() {
    let header = GzipHeader { modified: Some(42), name: Some("a.txt".into()), comment: Some("note".into()), extra: Some(vec![1, 2, 3]), operating_system: 3 };
    let encoded = header.encode();
    let (decoded, length) = GzipHeader::decode(&encoded).unwrap();
    assert_eq!(length, encoded.len());
    assert_eq!(decoded, header);
}

#[test]
fn round_trips_every_shape() {
    let codec = Gzip::default();
    for data in [Vec::new(), b"a".to_vec(), vec![b'a'; 5000], text(20000)] {
        let encoded = codec.compress(&data).unwrap();
        assert_eq!(codec.decompress(&encoded).unwrap(), data, "length {}", data.len());
    }
}

#[test]
fn a_broken_member_is_refused() {
    let codec = Gzip::default();
    assert_eq!(codec.decode(&[]), Ok(Vec::new()));
    assert_eq!(codec.decode(&[0x1F, 0x8B]), Err(GzipError::Truncated));
    let mut broken = SHORT;
    broken[0] = 0x1E;
    assert_eq!(codec.decode(&broken), Err(GzipError::Format));
    let mut broken = SHORT;
    let last = broken.len() - 5;
    broken[last] ^= 0xFF;
    assert_eq!(codec.decode(&broken), Err(GzipError::Checksum));
}

#[test]
fn a_limit_stops_a_bomb() {
    let bomb = Gzip::default().encode(&vec![0; 50000]).unwrap();
    let codec = Gzip { limit: Some(1000), ..Gzip::default() };
    assert_eq!(codec.decode(&bomb), Err(GzipError::Limit));
}

#[test]
fn streaming_matches_the_one_shot_call() {
    let codec = Gzip::default();
    let data = text(5000);
    let mut encoder = codec.encoder();
    for chunk in data.chunks(211) {
        encoder.update(chunk).unwrap();
    }
    let encoded = encoder.finalize().unwrap();
    assert_eq!(encoded, codec.compress(&data).unwrap());
    let mut decoder = codec.decoder();
    decoder.update(&encoded).unwrap();
    assert_eq!(decoder.finalize().unwrap(), data);
}
