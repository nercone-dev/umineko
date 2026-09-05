use umineko_codec_brotli::{BrotliContext, BrotliDictionary, BrotliTransform};

#[test]
fn the_dictionary_holds_every_word_the_format_names() {
    assert_eq!(BrotliDictionary::WORDS.len(), 122784, "the dictionary is the wrong size");
    assert_eq!(BrotliDictionary::word(4, 0).unwrap(), b"time");
    assert_eq!(BrotliDictionary::word(4, 1).unwrap(), b"down");
    assert_eq!(BrotliDictionary::word(5, 0).unwrap(), b"first");
    assert_eq!(BrotliDictionary::word(8, 0).unwrap(), b"position");
    assert_eq!(BrotliDictionary::word(24, 0).unwrap(), b"<script type=\"text/javas");
    let mut total = 0;
    for length in BrotliDictionary::MINIMUM..=BrotliDictionary::MAXIMUM {
        let count = BrotliDictionary::count(length);
        assert_eq!(BrotliDictionary::OFFSETS[length], total, "length {length} starts elsewhere");
        assert_eq!(BrotliDictionary::words(length).len(), count, "length {length}");
        total += count * length;
    }
    assert_eq!(total, BrotliDictionary::WORDS.len(), "the words do not fill the dictionary");
    assert!(BrotliDictionary::word(4, BrotliDictionary::count(4)).is_none());
    assert!(BrotliDictionary::word(3, 0).is_none());
    assert!(BrotliDictionary::word(25, 0).is_none());
}

#[test]
fn the_transforms_follow_the_shapes_the_format_names() {
    assert_eq!(BrotliTransform::TRANSFORMS.len(), 121);
    assert_eq!(BrotliTransform::at(0).unwrap().apply(b"time"), b"time");
    assert_eq!(BrotliTransform::at(1).unwrap().apply(b"time"), b"time ");
    assert_eq!(BrotliTransform::at(2).unwrap().apply(b"time"), b" time ");
    assert_eq!(BrotliTransform::at(3).unwrap().apply(b"time"), b"ime");
    assert_eq!(BrotliTransform::at(4).unwrap().apply(b"time"), b"Time ");
    assert!(BrotliTransform::at(121).is_none());
    for transform in BrotliTransform::TRANSFORMS.iter() {
        assert!(transform.prefix < BrotliTransform::AFFIXES.len());
        assert!(transform.suffix < BrotliTransform::AFFIXES.len());
    }
}

#[test]
fn every_context_model_names_the_contexts_the_format_holds() {
    assert_eq!(BrotliContext::LOOKUP.len(), 2048, "the lookup table is the wrong size");
    for byte in 0..=255u8 {
        assert_eq!(BrotliContext::LSB6.id(byte, 0), (byte & 0x3F) as usize, "lsb6 of {byte}");
        assert_eq!(BrotliContext::MSB6.id(byte, 0), (byte >> 2) as usize, "msb6 of {byte}");
        for second in [0u8, 65, 128, 200, 255] {
            assert_eq!(BrotliContext::LSB6.id(byte, second), (byte & 0x3F) as usize, "lsb6 never reads the second byte");
            for mode in [BrotliContext::UTF8, BrotliContext::Signed] {
                assert!(mode.id(byte, second) < BrotliContext::CONTEXTS, "{mode:?} names a context the format has no tree for");
            }
        }
    }
    // The model tuned for text sorts the ASCII characters the way the format describes.
    assert_eq!(BrotliContext::UTF8.id(b' ', b' '), 4 * 2);
    assert_eq!(BrotliContext::UTF8.id(b'.', b' '), 4 * 9);
    assert_eq!(BrotliContext::UTF8.id(b'a', b' '), 4 * 14);
    assert_eq!(BrotliContext::UTF8.id(b'b', b' '), 4 * 15);
    assert_eq!(BrotliContext::UTF8.id(b'a', b'b'), 4 * 14 + 3);
    for bits in 0..4 {
        assert_eq!(BrotliContext::from_bits(bits).unwrap().bits(), bits);
    }
    assert!(BrotliContext::from_bits(4).is_err());
}
