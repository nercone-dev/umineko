use umineko_crypto_idea::{IDEA, IDEAMode};

#[test]
fn parameters_follow_the_idea_specification() {
    assert_eq!((IDEA::KEY_SIZE, IDEA::BLOCK_SIZE), (16, 8));
}

#[test]
fn only_ecb_and_cbc_pad_the_plaintext() {
    for mode in [IDEAMode::ECB, IDEAMode::CBC, IDEAMode::CFB, IDEAMode::OFB] {
        assert_eq!(mode.padded(), matches!(mode, IDEAMode::ECB | IDEAMode::CBC));
    }
}
