use umineko_codec_huffman::{AdaptiveHuffman, HuffmanTree, StaticHuffman};

/// Every decoder reads untrusted input, so a broken stream must come back as an error
/// rather than a panic, and lengths that describe no code must be refused.
#[test]
fn malformed_streams_are_refused_without_panicking() {
    let codec = StaticHuffman::from_data(b"the quick brown fox").unwrap();
    let sample = codec.encode(b"the quick brown fox").unwrap();
    for seed in 0..3000usize {
        let mut stream = sample.clone();
        let index = (seed * 7) % stream.len();
        stream[index] ^= (seed % 251) as u8 + 1;
        let _ = codec.decode(&stream);
        let _ = codec.decode(&stream[..index]);
        let _ = AdaptiveHuffman::new().decode(&stream);
    }
    for seed in 0..2000usize {
        let lengths: Vec<u8> = (0..seed % 40).map(|index| ((seed * 13 + index * 7) % 18) as u8).collect();
        let _ = HuffmanTree::from_lengths(&lengths);
        let frequencies: Vec<u32> = (0..seed % 40).map(|index| ((seed * 17 + index) % 5) as u32).collect();
        let _ = HuffmanTree::from_frequencies(&frequencies, ((seed % 17) as u8).max(1));
    }
}
