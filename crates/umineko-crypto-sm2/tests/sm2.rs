use umineko_crypto_sm2::SM2;

#[test]
fn defaults_follow_rfc8998() {
    assert_eq!(SM2::DEFAULT_IDENTITY, b"1234567812345678");
    assert_eq!(SM2::PUBLIC_KEY_SIZE, 1 + 2 * 32);
    assert_eq!(SM2::PRIVATE_KEY_SIZE, 32);
    assert_eq!(SM2::request(SM2::DEFAULT_IDENTITY).context, SM2::DEFAULT_IDENTITY);
}
