use umineko_crypto_hmac::HMACHash;
use umineko_crypto_pbkdf2::PRF;

#[test]
fn hmac_is_a_prf_whose_output_is_the_digest() {
    for hash in HMACHash::ALL {
        assert_eq!(PRF::output_size(&hash), hash.digest_size(), "{hash}");
        assert_eq!(PRF::name(&hash), Some(hash.as_str()), "{hash}");
    }
}
