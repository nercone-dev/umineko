use umineko_codec_rle::{RLE, RLEError};

fn mixed(length: usize) -> Vec<u8> {
    (0..length).map(|index| match index % 97 { run if run < 60 => (index / 97 % 251) as u8, other => other as u8 }).collect()
}

#[test]
fn packbits_matches_the_apple_note() {
    let codec = RLE::default();
    let data = [0xAA, 0xAA, 0xAA, 0x80, 0x00, 0x2A, 0xAA, 0xAA, 0xAA, 0xAA, 0x80, 0x00, 0x2A, 0x22, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA];
    let encoded = [0xFE, 0xAA, 0x02, 0x80, 0x00, 0x2A, 0xFD, 0xAA, 0x03, 0x80, 0x00, 0x2A, 0x22, 0xF7, 0xAA];
    assert_eq!(codec.encode(&data).unwrap(), encoded);
    assert_eq!(codec.decode(&encoded).unwrap(), data);
}

#[test]
fn round_trips_every_shape() {
    let codec = RLE::default();
    for data in [Vec::new(), vec![0], vec![7; 1], vec![7; 2], vec![7; 3], vec![7; 128], vec![7; 129], vec![7; 5000], mixed(10000), (0..=255u8).collect()] {
        let encoded = codec.compress(&data).unwrap();
        assert_eq!(codec.decompress(&encoded).unwrap(), data, "length {}", data.len());
    }
}

#[test]
fn runs_shrink_and_noise_barely_grows() {
    let codec = RLE::default();
    assert!(codec.encode(&vec![9; 10000]).unwrap().len() < 200);
    let noise: Vec<u8> = (0..10000).map(|index| ((index * 37 + index / 13) % 251) as u8).collect();
    assert!(codec.encode(&noise).unwrap().len() <= noise.len() + noise.len() / 128 + 1);
}

#[test]
fn a_longer_minimum_run_keeps_short_runs_literal() {
    let codec = RLE { minimum_run: 5, limit: None };
    let data = [1, 1, 1, 2, 2, 2, 2, 2, 2, 3];
    let encoded = codec.encode(&data).unwrap();
    assert_eq!(codec.decode(&encoded).unwrap(), data);
    assert_eq!(encoded[0], 2);
}

#[test]
fn a_limit_stops_a_bomb() {
    let codec = RLE { minimum_run: 3, limit: Some(1000) };
    let bomb = RLE::default().encode(&vec![0; 5000]).unwrap();
    assert_eq!(codec.decode(&bomb), Err(RLEError::Limit));
}

#[test]
fn a_truncated_stream_is_refused() {
    let codec = RLE::default();
    assert_eq!(codec.decode(&[0x05, 1, 2]), Err(RLEError::Truncated));
    assert_eq!(codec.decode(&[0xFE]), Err(RLEError::Truncated));
    assert_eq!(codec.decode(&[0x80]).unwrap(), Vec::new());
}

#[test]
fn streaming_matches_the_one_shot_call() {
    let codec = RLE::default();
    let data = mixed(5000);
    let mut encoder = codec.encoder();
    for chunk in data.chunks(311) {
        assert!(encoder.update(chunk).unwrap().is_empty());
    }
    let encoded = encoder.finalize().unwrap();
    assert_eq!(encoded, codec.compress(&data).unwrap());
    let mut decoder = codec.decoder();
    for chunk in encoded.chunks(97) {
        decoder.update(chunk).unwrap();
    }
    assert_eq!(decoder.finalize().unwrap(), data);
}
