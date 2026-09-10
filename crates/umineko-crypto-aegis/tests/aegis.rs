use umineko_crypto_aegis::{AEGIS128L, AEGIS256, AEGISError};

#[test]
fn parameters_follow_the_aegis_specification() {
    assert_eq!((AEGIS128L::KEY_SIZE, AEGIS128L::NONCE_SIZE), (16, 16));
    assert_eq!((AEGIS256::KEY_SIZE, AEGIS256::NONCE_SIZE), (32, 32));
}

#[test]
fn only_128_and_256_bit_tags_are_accepted() {
    for tag_size in [16, 32] {
        assert_eq!(AEGIS128L::new(&[0; 16], tag_size).unwrap().tag_size(), tag_size);
        assert_eq!(AEGIS256::new(&[0; 32], tag_size).unwrap().tag_size(), tag_size);
    }
    for tag_size in [0, 8, 24, 64] {
        assert_eq!(AEGIS128L::new(&[0; 16], tag_size).unwrap_err(), AEGISError::Tag);
        assert_eq!(AEGIS256::new(&[0; 32], tag_size).unwrap_err(), AEGISError::Tag);
    }
}

#[test]
fn requests_carry_the_tag_size() {
    let cipher = AEGIS128L::new(&[0; 16], 32).unwrap();
    assert_eq!(cipher.request(&[0; 16], &[]).tag_size, Some(32));
    let cipher = AEGIS256::new(&[0; 32], 16).unwrap();
    assert_eq!(cipher.request(&[0; 32], &[]).tag_size, Some(16));
}
