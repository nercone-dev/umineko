use umineko_codec_lzss::{LZSS, LZSSError};

fn text(length: usize) -> Vec<u8> {
    let words = ["alpha ", "beta ", "gamma ", "delta ", "alpha ", "beta "];
    let mut data = Vec::new();
    while data.len() < length {
        data.extend_from_slice(words[data.len() % words.len()].as_bytes());
    }
    data.truncate(length);
    data
}

#[test]
fn round_trips_every_shape() {
    let codec = LZSS::default();
    for data in [Vec::new(), vec![0], vec![1, 2, 3], vec![7; 1000], text(10000), (0..=255u8).collect()] {
        let encoded = codec.compress(&data).unwrap();
        assert_eq!(codec.decompress(&encoded).unwrap(), data, "length {}", data.len());
    }
}

#[test]
fn repeats_shrink_well_below_the_input() {
    let codec = LZSS::default();
    let data = text(20000);
    let encoded = codec.encode(&data).unwrap();
    assert!(encoded.len() < data.len() / 4, "{} vs {}", encoded.len(), data.len());
    assert_eq!(codec.decode(&encoded).unwrap(), data);
}

#[test]
fn one_literal_costs_a_flag_and_a_byte() {
    let codec = LZSS::default();
    assert_eq!(codec.encode(b"a").unwrap(), [0b0000_0001, b'a']);
    assert_eq!(codec.encode(b"ab").unwrap(), [0b0000_0011, b'a', b'b']);
}

#[test]
fn other_thresholds_and_windows_round_trip() {
    for threshold in [2, 3, 4] {
        for window in [64, 1024, 4096, 32768] {
            let codec = LZSS { window, lookahead: threshold + 15, threshold, limit: None };
            let data = text(4000);
            let encoded = codec.encode(&data).unwrap();
            assert_eq!(codec.decode(&encoded).unwrap(), data, "threshold {threshold} window {window}");
        }
    }
}

#[test]
fn a_limit_stops_a_bomb() {
    let bomb = LZSS::default().encode(&vec![0; 5000]).unwrap();
    let codec = LZSS { limit: Some(1000), ..LZSS::default() };
    assert_eq!(codec.decode(&bomb), Err(LZSSError::Limit));
}

#[test]
fn a_broken_stream_is_refused() {
    let codec = LZSS::default();
    assert_eq!(codec.decode(&[0b0000_0000, 0x00]), Err(LZSSError::Truncated));
    assert_eq!(codec.decode(&[0b0000_0000, 0x05, 0x00]), Err(LZSSError::Format));
}

#[test]
fn streaming_matches_the_one_shot_call() {
    let codec = LZSS::default();
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
