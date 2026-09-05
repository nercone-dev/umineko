use umineko_crypto_des::{DES, DESError, DESMode, TripleDES};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap()).collect()
}

fn key<const N: usize>(text: &str) -> [u8; N] {
    let mut key = [0; N];
    key.copy_from_slice(&hex(text));
    key
}

fn sequence(length: usize) -> Vec<u8> {
    (0..length).map(|index| index as u8).collect()
}

fn single(text: &str) -> [u8; 24] {
    let mut key = [0; 24];
    for part in key.chunks_mut(8) {
        part.copy_from_slice(&hex(text));
    }
    key
}

#[test]
fn cipher_vectors() {
    let mut block = key::<8>("0123456789abcdef");
    DES::new(DESMode::ECB, &key("133457799bbcdff1")).encrypt_block(&mut block);
    assert_eq!(block, key::<8>("85e813540f0ab405"));
    DES::new(DESMode::ECB, &key("133457799bbcdff1")).decrypt_block(&mut block);
    assert_eq!(block, key::<8>("0123456789abcdef"));
    let mut block = [0; 8];
    DES::new(DESMode::ECB, &[0; 8]).encrypt_block(&mut block);
    assert_eq!(block, key::<8>("8ca64de9c1b123a7"));
}

#[test]
fn triple_vectors() {
    let mut block = key::<8>("0123456789abcdef");
    TripleDES::new(DESMode::ECB, &single("133457799bbcdff1")).encrypt_block(&mut block);
    assert_eq!(block, key::<8>("85e813540f0ab405"));
    let cipher = TripleDES::new(DESMode::ECB, &key("000102030405060708090a0b0c0d0e0f1011121314151617"));
    assert_eq!(&cipher.encrypt(&[], &sequence(32)).unwrap()[..32], &hex("58ed248f77f6b19e8c45c6184f56886365abd6ae1ad58520770b06204c457a3a")[..]);
}

#[test]
fn mode_vectors() {
    let triple = key::<24>("000102030405060708090a0b0c0d0e0f1011121314151617");
    let nonce = sequence(8);
    for (mode, expected) in [
        (DESMode::CBC, "894bc3085426a441f27f73ae26abbf74bd8aed47a8d26334ef7fb5aa2551c31f"),
        (DESMode::CFB, "58ec268c73f3b799c01ef19072afbffdd2be30c4253c973067c2fbbbef7e77bf"),
        (DESMode::OFB, "58ec268c73f3b7994fd0bd414357e862413ca69d5c94e282545029718fb5bd64"),
    ] {
        let cipher = TripleDES::new(mode, &triple);
        assert_eq!(&cipher.encrypt(&nonce, &sequence(32)).unwrap()[..32], &hex(expected)[..], "{mode}");
    }
    for (mode, expected) in [
        (DESMode::CBC, "a5173ad5957b43705a8cfc7ef9266f57f758df231703ec1bc7695d7de9048661"),
        (DESMode::OFB, "e1b344e6a3c24abbddf9842e37f72d8f13070a04b74cacbbe45e4d31e559199b"),
        (DESMode::CFB, "e1b344e6a3c24abb7a15166ec0342e307737c5e6f63cbd27c14b3652da99cf91"),
    ] {
        let cipher = DES::new(mode, &key::<8>("0001020304050607"));
        assert_eq!(&cipher.encrypt(&nonce, &sequence(32)).unwrap()[..32], &hex(expected)[..], "{mode}");
    }
}

#[test]
fn modes_round_trip() {
    for mode in [DESMode::ECB, DESMode::CBC, DESMode::CFB, DESMode::OFB, DESMode::CTR] {
        let nonce = sequence(mode.nonce_size().unwrap_or(0));
        for length in [0, 1, 7, 8, 9, 32, 100] {
            let plaintext = sequence(length);
            let cipher = DES::new(mode, &key("0001020304050607"));
            let ciphertext = cipher.encrypt(&nonce, &plaintext).unwrap();
            assert_eq!(cipher.decrypt(&nonce, &ciphertext).unwrap(), plaintext, "{mode} {length}");
            let cipher = TripleDES::new(mode, &key("000102030405060708090a0b0c0d0e0f1011121314151617"));
            let ciphertext = cipher.encrypt(&nonce, &plaintext).unwrap();
            assert_eq!(cipher.decrypt(&nonce, &ciphertext).unwrap(), plaintext, "{mode} {length}");
        }
    }
}

#[test]
fn failures() {
    let cipher = DES::new(DESMode::CBC, &key("0001020304050607"));
    assert_eq!(cipher.encrypt(&sequence(4), &sequence(8)), Err(DESError::Nonce));
    assert_eq!(cipher.decrypt(&sequence(8), &[0; 12]), Err(DESError::Length));
    assert_eq!(cipher.decrypt(&sequence(8), &[]), Err(DESError::Length));
    let mut ciphertext = cipher.encrypt(&sequence(8), &sequence(8)).unwrap();
    ciphertext[8] ^= 0xff;
    assert_eq!(cipher.decrypt(&sequence(8), &ciphertext), Err(DESError::Padding));
}
