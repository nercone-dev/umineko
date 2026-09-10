use umineko_crypto_ascon::AsconHash256;
use umineko_crypto_hmac::HMACHash;
use umineko_hash_md::MD5;
use umineko_hash_sha::{SHA1, SHA2_224, SHA2_256, SHA2_384, SHA2_512, SHA2_512_224, SHA2_512_256, SHA3_224, SHA3_256, SHA3_384, SHA3_512};
use umineko_hash_sm3::SM3;
use umineko_hash_streebog::{Streebog256, Streebog512};

#[test]
fn hash_sizes_follow_their_specifications() {
    let expected = [
        (HMACHash::MD5, 16, 64),
        (HMACHash::SHA1, 20, 64),
        (HMACHash::SHA2_224, 28, 64),
        (HMACHash::SHA2_256, 32, 64),
        (HMACHash::SHA2_384, 48, 128),
        (HMACHash::SHA2_512, 64, 128),
        (HMACHash::SHA2_512_224, 28, 128),
        (HMACHash::SHA2_512_256, 32, 128),
        (HMACHash::SHA3_224, 28, 144),
        (HMACHash::SHA3_256, 32, 136),
        (HMACHash::SHA3_384, 48, 104),
        (HMACHash::SHA3_512, 64, 72),
        (HMACHash::SM3, 32, 64),
        (HMACHash::Streebog256, 32, 64),
        (HMACHash::Streebog512, 64, 64),
        (HMACHash::AsconHash256, 32, 64),
    ];
    assert_eq!(HMACHash::ALL.len(), expected.len());
    for (hash, digest_size, block_size) in expected {
        assert_eq!(hash.digest_size(), digest_size, "{hash}");
        assert_eq!(hash.block_size(), block_size, "{hash}");
    }
}

#[test]
fn the_block_size_is_at_least_the_digest_size_by_rfc2104() {
    for hash in HMACHash::ALL {
        assert!(hash.block_size() >= hash.digest_size(), "{hash}");
    }
}

#[test]
fn hash_names_match_the_hash_crates() {
    let expected = [
        (HMACHash::MD5, MD5::NAME),
        (HMACHash::SHA1, SHA1::NAME),
        (HMACHash::SHA2_224, SHA2_224::NAME),
        (HMACHash::SHA2_256, SHA2_256::NAME),
        (HMACHash::SHA2_384, SHA2_384::NAME),
        (HMACHash::SHA2_512, SHA2_512::NAME),
        (HMACHash::SHA2_512_224, SHA2_512_224::NAME),
        (HMACHash::SHA2_512_256, SHA2_512_256::NAME),
        (HMACHash::SHA3_224, SHA3_224::NAME),
        (HMACHash::SHA3_256, SHA3_256::NAME),
        (HMACHash::SHA3_384, SHA3_384::NAME),
        (HMACHash::SHA3_512, SHA3_512::NAME),
        (HMACHash::SM3, SM3::NAME),
        (HMACHash::Streebog256, Streebog256::NAME),
        (HMACHash::Streebog512, Streebog512::NAME),
        (HMACHash::AsconHash256, AsconHash256::NAME),
    ];
    for (hash, name) in expected {
        assert_eq!(hash.hash_name(), name);
        assert_eq!(HMACHash::from_name(hash.as_str()), Some(hash));
    }
    assert_eq!(HMACHash::from_name("SHA-256"), None);
}

#[test]
fn truncated_tags_keep_at_least_half_the_output_and_80_bits_by_rfc2104() {
    for hash in HMACHash::ALL {
        assert_eq!(hash.minimum_tag_size(), core::cmp::max(hash.digest_size().div_ceil(2), 10), "{hash}");
        assert!(hash.minimum_tag_size() * 8 >= 80, "{hash}");
        assert!(hash.minimum_tag_size() * 2 >= hash.digest_size(), "{hash}");
    }
}
