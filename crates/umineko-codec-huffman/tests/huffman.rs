use umineko_codec_huffman::{AdaptiveHuffman, Huffman, HuffmanError, HuffmanTree, StaticHuffman};

fn data(length: usize) -> Vec<u8> {
    (0..length).map(|index| ((index * index / 7 + index) % 251) as u8).collect()
}

#[test]
fn lengths_describe_canonical_codes() {
    let tree = HuffmanTree::from_lengths(&[3, 3, 3, 3, 3, 2, 4, 4]).unwrap();
    assert_eq!(tree.encode(5), Some((0b00, 2)));
    assert_eq!(tree.encode(0), Some((0b010, 3)));
    assert_eq!(tree.encode(1), Some((0b011, 3)));
    assert_eq!(tree.encode(6), Some((0b1110, 4)));
    assert_eq!(tree.encode(7), Some((0b1111, 4)));
    assert_eq!(tree.decode(0b00, 2), Some(5));
    assert_eq!(tree.decode(0b1111, 4), Some(7));
    assert_eq!(tree.decode(0b1111, 3), None);
}

#[test]
fn lengths_that_oversubscribe_are_rejected() {
    assert_eq!(HuffmanTree::from_lengths(&[1, 1, 1]), Err(HuffmanError::Lengths));
    assert_eq!(HuffmanTree::from_lengths(&[1, 2, 2, 2]), Err(HuffmanError::Lengths));
    assert!(HuffmanTree::from_lengths(&[1, 2, 3, 3]).is_ok());
}

#[test]
fn frequencies_build_a_code_that_favours_the_common_symbols() {
    let mut frequencies = vec![0; 8];
    frequencies[0] = 100;
    frequencies[1] = 20;
    frequencies[2] = 5;
    frequencies[3] = 1;
    let tree = HuffmanTree::from_frequencies(&frequencies, 15).unwrap();
    assert_eq!(tree.lengths()[0], 1);
    assert!(tree.lengths()[1] < tree.lengths()[2]);
    assert!(tree.lengths()[2] <= tree.lengths()[3]);
    assert_eq!(tree.lengths()[4], 0);
}

#[test]
fn frequencies_never_build_a_code_past_the_limit() {
    let frequencies: Vec<u32> = (0..32).map(|index| 1u32 << index).collect();
    for maximum in [5, 8, 15] {
        let tree = HuffmanTree::from_frequencies(&frequencies, maximum).unwrap();
        assert!(tree.lengths().iter().all(|length| *length <= maximum), "limit {maximum}");
        assert!(tree.lengths().iter().all(|length| *length > 0));
    }
}

#[test]
fn static_coding_round_trips() {
    for length in [0, 1, 2, 100, 5000] {
        let data = data(length);
        let codec = StaticHuffman::from_data(&data).unwrap();
        let encoded = codec.encode(&data).unwrap();
        assert_eq!(codec.decode(&encoded).unwrap(), data, "at {length}");
    }
}

#[test]
fn static_coding_shrinks_a_skewed_stream() {
    let data: Vec<u8> = (0..10000).map(|index| if index % 10 == 0 { b'b' } else { b'a' }).collect();
    let codec = StaticHuffman::from_data(&data).unwrap();
    let encoded = codec.encode(&data).unwrap();
    assert!(encoded.len() < data.len() / 2);
    assert_eq!(codec.decode(&encoded).unwrap(), data);
}

#[test]
fn adaptive_coding_round_trips() {
    for length in [0, 1, 300] {
        let data = data(length);
        let mut encoder = AdaptiveHuffman::new();
        let encoded = encoder.encode(&data).unwrap();
        let mut decoder = AdaptiveHuffman::new();
        assert_eq!(decoder.decode(&encoded).unwrap(), data, "at {length}");
    }
}

#[test]
fn the_closing_symbol_ends_a_stream() {
    assert_eq!(Huffman::END, 256);
    let codec = StaticHuffman::from_data(b"abc").unwrap();
    let mut encoded = codec.encode(b"abc").unwrap();
    encoded.extend_from_slice(&[0xFF, 0xFF]);
    assert_eq!(codec.decode(&encoded).unwrap(), b"abc");
}
