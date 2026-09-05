use umineko_codec_lz77::{LZ77, LZ77Error, LZ77Matcher};

fn text(length: usize) -> Vec<u8> {
    let words = ["the ", "quick ", "brown ", "fox ", "jumps ", "over ", "the ", "lazy ", "dog "];
    let mut data = Vec::new();
    while data.len() < length {
        data.extend_from_slice(words[data.len() % words.len()].as_bytes());
    }
    data.truncate(length);
    data
}

#[test]
fn round_trips_every_shape() {
    let codec = LZ77::default();
    for data in [Vec::new(), vec![0], vec![1, 2, 3], vec![7; 1000], text(10000), (0..=255u8).collect()] {
        let encoded = codec.compress(&data).unwrap();
        assert_eq!(codec.decompress(&encoded).unwrap(), data, "length {}", data.len());
    }
}

#[test]
fn repeats_shrink() {
    let codec = LZ77::default();
    let data = text(20000);
    let encoded = codec.encode(&data).unwrap();
    assert!(encoded.len() < data.len(), "{} vs {}", encoded.len(), data.len());
    assert_eq!(codec.decode(&encoded).unwrap(), data);
}

#[test]
fn overlapping_matches_round_trip() {
    let codec = LZ77::default();
    let data = vec![0xAB; 300];
    let encoded = codec.encode(&data).unwrap();
    assert!(encoded.len() < 40);
    assert_eq!(codec.decode(&encoded).unwrap(), data);
}

#[test]
fn a_broken_stream_is_refused() {
    let codec = LZ77::default();
    assert_eq!(codec.decode(&[0, 0, 0, 0]), Err(LZ77Error::Truncated));
    assert_eq!(codec.decode(&[5, 0, 3, 0, b'a']), Err(LZ77Error::Format));
    assert_eq!(codec.decode(&[0, 0, 3, 0, b'a']), Err(LZ77Error::Format));
}

#[test]
fn a_limit_stops_a_bomb() {
    let bomb = LZ77::default().encode(&vec![0; 5000]).unwrap();
    let codec = LZ77 { limit: Some(1000), ..LZ77::default() };
    assert_eq!(codec.decode(&bomb), Err(LZ77Error::Limit));
}

#[test]
fn the_matcher_finds_the_longest_earlier_copy() {
    let data = b"abcdefabcdefabcdef";
    let mut matcher = LZ77Matcher::new(4096, 258, data.len());
    for offset in 0..6 {
        matcher.insert(data, offset);
    }
    assert_eq!(matcher.find(data, 6, 3, data.len()), Some((6, 12)));
    assert_eq!(matcher.find(data, 6, 3, 4), Some((6, 4)));
}

#[test]
fn streaming_matches_the_one_shot_call() {
    let codec = LZ77::default();
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
