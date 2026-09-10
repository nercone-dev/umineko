use umineko_crypto_chacha20::{ChaCha20, ChaCha20Poly1305, XChaCha20, XChaCha20Poly1305};

#[test]
fn chacha20_poly1305_follows_rfc8439() {
    assert_eq!((ChaCha20Poly1305::KEY_SIZE, ChaCha20Poly1305::NONCE_SIZE, ChaCha20Poly1305::TAG_SIZE), (32, 12, 16));
    assert_eq!(ChaCha20Poly1305::KEY_SIZE, ChaCha20::KEY_SIZE);
    assert_eq!(ChaCha20Poly1305::NONCE_SIZE, ChaCha20::NONCE_SIZE);
}

#[test]
fn xchacha20_poly1305_extends_the_nonce_to_192_bits() {
    assert_eq!((XChaCha20Poly1305::KEY_SIZE, XChaCha20Poly1305::NONCE_SIZE, XChaCha20Poly1305::TAG_SIZE), (32, 24, 16));
    assert_eq!(XChaCha20Poly1305::NONCE_SIZE, XChaCha20::NONCE_SIZE);
}

#[test]
fn requests_carry_the_nonce_and_associated_data() {
    let cipher = ChaCha20Poly1305::new(&[7; 32]);
    let request = cipher.request(&[1; 12], b"header");
    assert_eq!(request.algorithm, ChaCha20Poly1305::NAME);
    assert_eq!((request.key, request.nonce, request.associated), (&[7; 32][..], &[1; 12][..], &b"header"[..]));
}
