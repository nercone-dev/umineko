use umineko_codec_lzma::LZMA;

#[test]
fn malformed_streams_never_hang() {
    let codec = LZMA::default();
    for seed in 0..2000u32 {
        let mut stream = LZMA::default().encode(b"the quick brown fox").unwrap();
        let index = (seed as usize * 7) % stream.len();
        stream[index] ^= (seed % 251) as u8 + 1;
        let _ = codec.decode(&stream);
    }
    for length in 0..64 {
        let stream: Vec<u8> = (0..length).map(|index| (index * 37 % 253) as u8).collect();
        let _ = codec.decode(&stream);
    }
}
