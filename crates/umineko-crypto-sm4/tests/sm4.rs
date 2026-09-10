use umineko_crypto_sm4::{SM4, SM4Mode};

#[test]
fn parameters_follow_gb_t_32907() {
    assert_eq!((SM4::KEY_SIZE, SM4::BLOCK_SIZE), (16, 16));
}

#[test]
fn gcm_and_ccm_are_the_authenticated_modes() {
    for mode in [SM4Mode::ECB, SM4Mode::CBC, SM4Mode::CFB, SM4Mode::OFB, SM4Mode::CTR, SM4Mode::GCM, SM4Mode::CCM] {
        assert_eq!(mode.authenticated(), matches!(mode, SM4Mode::GCM | SM4Mode::CCM));
        assert_eq!(mode.padded(), matches!(mode, SM4Mode::ECB | SM4Mode::CBC));
    }
}
