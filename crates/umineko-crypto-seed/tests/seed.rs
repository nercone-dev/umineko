use umineko_crypto_seed::{SEED, SEEDMode};

#[test]
fn parameters_follow_rfc4269() {
    assert_eq!((SEED::KEY_SIZE, SEED::BLOCK_SIZE), (16, 16));
}

#[test]
fn only_ecb_and_cbc_pad_the_plaintext() {
    for mode in [SEEDMode::ECB, SEEDMode::CBC, SEEDMode::CFB, SEEDMode::OFB, SEEDMode::CTR] {
        assert_eq!(mode.padded(), matches!(mode, SEEDMode::ECB | SEEDMode::CBC));
    }
}
