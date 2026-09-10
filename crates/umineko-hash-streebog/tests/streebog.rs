use umineko_hash_streebog::{Streebog, Streebog256, Streebog512};

#[test]
fn sizes_follow_rfc6986() {
    assert_eq!((Streebog256::DIGEST_SIZE, Streebog256::BLOCK_SIZE), (32, 64));
    assert_eq!((Streebog512::DIGEST_SIZE, Streebog512::BLOCK_SIZE), (64, 64));
    assert_eq!(Streebog::V256.digest_size(), Streebog256::DIGEST_SIZE);
    assert_eq!(Streebog::V512.digest_size(), Streebog512::DIGEST_SIZE);
    assert_eq!(Streebog::V256.block_size(), Streebog256::BLOCK_SIZE);
    assert_eq!(Streebog::V512.block_size(), Streebog512::BLOCK_SIZE);
}

#[test]
fn names_round_trip() {
    for (variant, name) in [(Streebog::V256, Streebog256::NAME), (Streebog::V512, Streebog512::NAME)] {
        assert_eq!(variant.as_str(), name);
        assert_eq!(Streebog::from_name(name), Some(variant));
    }
    assert_eq!(Streebog::from_name("Streebog-384"), None);
}
