use umineko_crypto_hmac::HMACHash;
use umineko_crypto_kdftree::{KDFTree, KDFTreeError};

#[test]
fn the_counter_is_one_to_four_bytes_by_rfc7836() {
    for counter_size in [0, 5, 8] {
        assert_eq!(KDFTree::new(HMACHash::Streebog256, counter_size), Err(KDFTreeError::Counter), "{counter_size}");
    }
    for counter_size in 1..=4 {
        let kdf = KDFTree::new(HMACHash::Streebog256, counter_size).unwrap();
        assert_eq!(kdf.counter_size(), counter_size);
        assert_eq!(kdf.maximum_blocks(), (1u64 << (8 * counter_size)) - 1);
    }
}

#[test]
fn kdf_gostr3411_2012_256_input_follows_rfc7836() {
    let kdf = KDFTree::new(HMACHash::Streebog256, 1).unwrap();
    let seed = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let mut expected = vec![0x01];
    expected.extend_from_slice(b"level1");
    expected.push(0x00);
    expected.extend_from_slice(&seed);
    expected.extend_from_slice(&[0x01, 0x00]);
    assert_eq!(kdf.input(1, b"level1", &seed, 32), Ok(expected));
}

#[test]
fn the_counter_and_length_encodings_follow_rfc7836() {
    let kdf = KDFTree::new(HMACHash::Streebog256, 4).unwrap();
    assert_eq!(kdf.input(2, b"kdf tree", &[0xAA], 64), Ok([&[0x00, 0x00, 0x00, 0x02][..], b"kdf tree", &[0x00, 0xAA], &[0x02, 0x00]].concat()));
    let kdf = KDFTree::new(HMACHash::Streebog256, 2).unwrap();
    assert_eq!(kdf.input(0x0102, b"", &[], 1), Ok(vec![0x01, 0x02, 0x00, 0x08]));
    assert_eq!(kdf.input(1, b"", &[], 0x20000), Ok(vec![0x00, 0x01, 0x00, 0x10, 0x00, 0x00]));
}

#[test]
fn the_iteration_counter_starts_at_one_and_fits_in_r_bytes_by_rfc7836() {
    let kdf = KDFTree::new(HMACHash::Streebog256, 1).unwrap();
    assert_eq!(kdf.input(0, b"label", b"seed", 32), Err(KDFTreeError::Counter));
    assert!(kdf.input(255, b"label", b"seed", 32).is_ok());
    assert_eq!(kdf.input(256, b"label", b"seed", 32), Err(KDFTreeError::Counter));
}

#[test]
fn the_output_length_is_bounded_by_the_counter_size_by_rfc7836() {
    let kdf = KDFTree::new(HMACHash::Streebog256, 1).unwrap();
    assert_eq!(kdf.derive(&[0; 32], b"label", b"seed", &mut vec![0; 255 * 32 + 1]), Err(KDFTreeError::Length));
}

#[test]
fn the_provider_request_names_the_prf_and_the_counter_size() {
    let request = KDFTree::new(HMACHash::Streebog256, 3).unwrap().request().unwrap();
    assert_eq!(request.algorithm, "KDF_TREE");
    assert_eq!(request.prf, Some("HMAC-Streebog-256"));
    assert_eq!(request.counter_size, 3);
}
