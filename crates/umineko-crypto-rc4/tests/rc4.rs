use umineko_crypto_rc4::{RC4, RC4Error};

#[test]
fn keys_between_1_and_256_bytes_are_accepted() {
    assert_eq!(RC4::new(&[]).unwrap_err(), RC4Error::Key);
    assert!(RC4::new(&[0; 1]).is_ok());
    assert!(RC4::new(&[0; 5]).is_ok());
    assert!(RC4::new(&[0; 256]).is_ok());
    assert_eq!(RC4::new(&[0; 257]).unwrap_err(), RC4Error::Key);
    assert_eq!(RC4::new(&[0; 16]).unwrap().position(), 0);
}
