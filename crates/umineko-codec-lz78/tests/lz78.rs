use umineko_codec_lz78::{LZ78, LZ78Error};

fn text(length: usize) -> Vec<u8> {
    let words = ["one ", "two ", "three ", "one ", "two "];
    let mut data = Vec::new();
    while data.len() < length {
        data.extend_from_slice(words[data.len() % words.len()].as_bytes());
    }
    data.truncate(length);
    data
}

#[test]
fn round_trips_every_shape() {
    let codec = LZ78::default();
    for data in [Vec::new(), vec![0], vec![1, 2, 3], vec![7; 1000], text(10000), (0..=255u8).collect()] {
        let encoded = codec.compress(&data).unwrap();
        assert_eq!(codec.decompress(&encoded).unwrap(), data, "length {}", data.len());
    }
}

#[test]
fn phrases_grow_one_byte_at_a_time() {
    let codec = LZ78::default();
    let encoded = codec.encode(b"aaaa").unwrap();
    assert_eq!(encoded, [0, 0, 0, 0, b'a', 1, 0, 0, 0, b'a', 1, 0, 0, 0]);
    assert_eq!(codec.decode(&encoded).unwrap(), b"aaaa");
}

#[test]
fn repeats_shrink() {
    let codec = LZ78::default();
    let data = text(40000);
    let encoded = codec.encode(&data).unwrap();
    assert!(encoded.len() < data.len(), "{} vs {}", encoded.len(), data.len());
    assert_eq!(codec.decode(&encoded).unwrap(), data);
}

#[test]
fn a_small_dictionary_starts_over_on_both_sides() {
    let codec = LZ78 { dictionary: 16, limit: None };
    let data = text(4000);
    let encoded = codec.encode(&data).unwrap();
    assert_eq!(codec.decode(&encoded).unwrap(), data);
}

#[test]
fn a_broken_stream_is_refused() {
    let codec = LZ78::default();
    assert_eq!(codec.decode(&[0, 0, 0]), Err(LZ78Error::Truncated));
    assert_eq!(codec.decode(&[9, 0, 0, 0, b'a']), Err(LZ78Error::Format));
}

#[test]
fn a_limit_stops_a_bomb() {
    let bomb = LZ78::default().encode(&vec![0; 5000]).unwrap();
    let codec = LZ78 { limit: Some(1000), ..LZ78::default() };
    assert_eq!(codec.decode(&bomb), Err(LZ78Error::Limit));
}

#[test]
fn streaming_matches_the_one_shot_call() {
    let codec = LZ78::default();
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
