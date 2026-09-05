use umineko_codec_lz4::LZ4;

/// Every decoder reads untrusted input, so a broken stream must come back as an error
/// rather than a panic, and must never keep the decoder running forever.
#[test]
fn malformed_streams_are_refused_without_panicking() {
    let codec = LZ4::default();
    let sample = codec.encode(b"the quick brown fox jumps over the lazy dog, and then does it again").unwrap();
    for seed in 0..3000usize {
        let mut stream = sample.clone();
        let index = (seed * 7) % stream.len().max(1);
        if index < stream.len() {
            stream[index] ^= (seed % 251) as u8 + 1;
        }
        let _ = codec.decode(&stream);
        let _ = codec.decode(&stream[..index]);
    }
    for length in 0..96usize {
        let stream: Vec<u8> = (0..length).map(|index| (index * 37 % 253) as u8).collect();
        let _ = codec.decode(&stream);
        let ones: Vec<u8> = vec![0xFF; length];
        let _ = codec.decode(&ones);
        let zeroes: Vec<u8> = vec![0x00; length];
        let _ = codec.decode(&zeroes);
    }
}
