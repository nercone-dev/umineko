use umineko_crypto_chacha20::{ChaCha20, XChaCha20};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap()).collect()
}

fn key<const N: usize>(text: &str) -> [u8; N] {
    let mut key = [0; N];
    key.copy_from_slice(&hex(text));
    key
}

#[test]
fn block_vector() {
    let cipher = ChaCha20::new(&key("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), &key("000000090000004a00000000"), 1);
    assert_eq!(cipher.block(1).to_vec(), hex("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"));
}

#[test]
fn stream_vector() {
    let mut cipher = ChaCha20::new(&key("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), &key("000000000000004a00000000"), 1);
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let ciphertext = cipher.apply(plaintext);
    assert_eq!(ciphertext, hex("6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"));
    let mut cipher = ChaCha20::new(&key("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), &key("000000000000004a00000000"), 1);
    assert_eq!(cipher.apply(&ciphertext), plaintext);
}

#[test]
fn counter_advances() {
    let mut cipher = ChaCha20::new(&[7; 32], &[9; 12], 0);
    let long = cipher.apply(&[0; 192]);
    assert_eq!(cipher.counter(), 3);
    let mut cipher = ChaCha20::new(&[7; 32], &[9; 12], 0);
    let mut parts = Vec::new();
    for _ in 0..3 {
        parts.extend_from_slice(&cipher.apply(&[0; 64]));
    }
    assert_eq!(parts, long);
    cipher.reset(0);
    assert_eq!(cipher.counter(), 0);
    assert_eq!(cipher.apply(&[0; 64]), &long[..64]);
}

#[test]
fn extended_nonce() {
    assert_eq!(
        XChaCha20::subkey(&key("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), &key("000000090000004a0000000031415927")).to_vec(),
        hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
    );
    let mut cipher = XChaCha20::new(&[3; 32], &[5; 24], 0);
    let ciphertext = cipher.apply(&[0; 100]);
    let mut cipher = XChaCha20::new(&[3; 32], &[5; 24], 0);
    assert_eq!(cipher.apply(&ciphertext), [0; 100]);
    assert_eq!(cipher.counter(), 2);
}
