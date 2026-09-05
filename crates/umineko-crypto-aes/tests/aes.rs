use umineko_crypto_aes::{AES, AES128, AES192, AES256, AESError, AESMode};

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

#[test]
fn cipher_vectors() {
    let mut block = key::<16>("00112233445566778899aabbccddeeff");
    AES128::new(AESMode::ECB, &key("000102030405060708090a0b0c0d0e0f")).encrypt_block(&mut block);
    assert_eq!(block, key::<16>("69c4e0d86a7b0430d8cdb78070b4c55a"));
    AES128::new(AESMode::ECB, &key("000102030405060708090a0b0c0d0e0f")).decrypt_block(&mut block);
    assert_eq!(block, key::<16>("00112233445566778899aabbccddeeff"));
    let mut block = key::<16>("00112233445566778899aabbccddeeff");
    AES192::new(AESMode::ECB, &key("000102030405060708090a0b0c0d0e0f1011121314151617")).encrypt_block(&mut block);
    assert_eq!(block, key::<16>("dda97ca4864cdfe06eaf70a0ec0d7191"));
    let mut block = key::<16>("00112233445566778899aabbccddeeff");
    AES256::new(AESMode::ECB, &key("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")).encrypt_block(&mut block);
    assert_eq!(block, key::<16>("8ea2b7ca516745bfeafc49904b496089"));
}

#[test]
fn galois_vectors() {
    let cipher = AES128::new(AESMode::GCM, &[0; 16]);
    assert_eq!(cipher.encrypt(&[0; 12], &[], &[]).unwrap(), hex("58e2fccefa7e3061367f1d57a4e7455a"));
    assert_eq!(cipher.encrypt(&[0; 12], &[], &[0; 16]).unwrap(), hex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf"));
    let cipher = AES128::new(AESMode::GCM, &key("feffe9928665731c6d6a8f9467308308"));
    let plaintext = hex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
    let ciphertext = cipher.encrypt(&hex("cafebabefacedbaddecaf888"), &[], &plaintext).unwrap();
    assert_eq!(ciphertext, hex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f59854d5c2af327cd64a62cf35abd2ba6fab4"));
    assert_eq!(cipher.decrypt(&hex("cafebabefacedbaddecaf888"), &[], &ciphertext).unwrap(), plaintext);
    let associated = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let short = &plaintext[..60];
    let ciphertext = cipher.encrypt(&hex("cafebabefacedbaddecaf888"), &associated, short).unwrap();
    assert_eq!(ciphertext, hex("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47"));
    assert_eq!(cipher.decrypt(&hex("cafebabefacedbaddecaf888"), &associated, &ciphertext).unwrap(), short);
}

#[test]
fn galois_reference() {
    let ciphertext = AES128::new(AESMode::GCM, &key("000102030405060708090a0b0c0d0e0f")).encrypt(&sequence(12), &sequence(20), &sequence(32)).unwrap();
    assert_eq!(ciphertext, hex("936da5cd621ef15343db6b813aae7e07a33708f547f8ebe1fe38eb360859bc73f17d8132a8cd57505e99791bb3ed5811"));
    let ciphertext = AES128::new(AESMode::GCM, &key("000102030405060708090a0b0c0d0e0f")).encrypt(&sequence(8), &sequence(20), &sequence(32)).unwrap();
    assert_eq!(ciphertext, hex("c74a2d76f6d3544bbff1c7eea93f42837a013b020359fb7145a79c8672ea8a6e6cced28966da05f2b6b0131c22e9af74"));
    let ciphertext = AES256::new(AESMode::GCM, &key("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")).encrypt(&sequence(12), &sequence(20), &sequence(32)).unwrap();
    assert_eq!(ciphertext, hex("4703d418c1e0c41c85489d80bde4766293c79527e46e496b207eff9e01741ead1b5351d113edac0c99d37bc0f21faa43"));
}

#[test]
fn chained_reference() {
    let cipher = AES128::new(AESMode::CCM, &key("000102030405060708090a0b0c0d0e0f"));
    assert_eq!(cipher.encrypt(&sequence(12), &sequence(20), &sequence(32)).unwrap(), hex("3314f164d885c2b6791ac3eb0ee78b8f7c470b21df11a12f567e5686ec3db5ae530a5973716d928fea0689fc6bbb75d4"));
    assert_eq!(cipher.encrypt(&sequence(13), &sequence(20), &sequence(32)).unwrap(), hex("1635b68b570cfc85529e39ac913910d7f3111631623867f134e6e441904fd504b6d3c92666d9f0c56c27eb95b00d478e"));
    assert_eq!(cipher.encrypt(&sequence(7), &sequence(20), &sequence(32)).unwrap(), hex("5715b1ef39830708a405a5ee98eb09b0cf21098c7b865325998ba6e70eb59e957516674de56463b7245e0e4441208867"));
    assert_eq!(cipher.encrypt(&sequence(12), &[], &[]).unwrap(), hex("a9452a1d712c00a7b1c3fab799f1bc51"));
    let cipher = AES192::new(AESMode::CCM, &key("000102030405060708090a0b0c0d0e0f1011121314151617"));
    assert_eq!(cipher.encrypt(&sequence(12), &sequence(20), &sequence(32)).unwrap(), hex("1f94e0c048b9dbb91dbc2c30a5eccae6dabc92ec115ba3adee474085f00c4fb6cbea964405e9d6f89d1da41f32589d17"));
    let cipher = AES256::new(AESMode::CCM, &key("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
    assert_eq!(cipher.encrypt(&sequence(12), &sequence(20), &sequence(32)).unwrap(), hex("8ad4ba153a2acf90a4c0bb28013d524b2d6504662d604eae7dbc994e89053c6c7e5c0b93ead6d75b41d2ef2483bd7764"));
}

#[test]
fn modes_round_trip() {
    for mode in [AESMode::ECB, AESMode::CBC, AESMode::CFB, AESMode::OFB, AESMode::CTR, AESMode::GCM, AESMode::CCM] {
        let nonce = sequence(mode.nonce_size().unwrap_or(0));
        for length in [0, 1, 15, 16, 17, 64, 100] {
            let plaintext = sequence(length);
            let cipher = AES128::new(mode, &key("000102030405060708090a0b0c0d0e0f"));
            let ciphertext = cipher.encrypt(&nonce, &sequence(3), &plaintext).unwrap();
            assert_eq!(cipher.decrypt(&nonce, &sequence(3), &ciphertext).unwrap(), plaintext, "{mode} {length}");
            let cipher = AES256::new(mode, &key("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
            let ciphertext = cipher.encrypt(&nonce, &sequence(3), &plaintext).unwrap();
            assert_eq!(cipher.decrypt(&nonce, &sequence(3), &ciphertext).unwrap(), plaintext, "{mode} {length}");
        }
    }
}

#[test]
fn authentication_failure() {
    for mode in [AESMode::GCM, AESMode::CCM] {
        let cipher = AES128::new(mode, &key("000102030405060708090a0b0c0d0e0f"));
        let nonce = sequence(12);
        let mut ciphertext = cipher.encrypt(&nonce, &sequence(3), &sequence(32)).unwrap();
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 1;
        assert_eq!(cipher.decrypt(&nonce, &sequence(3), &ciphertext), Err(AESError::Authentication), "{mode}");
        ciphertext[last] ^= 1;
        assert_eq!(cipher.decrypt(&nonce, &sequence(4), &ciphertext), Err(AESError::Authentication), "{mode}");
        assert_eq!(cipher.decrypt(&nonce, &sequence(3), &ciphertext[..8]), Err(AESError::Length), "{mode}");
    }
}

#[test]
fn padding_failure() {
    let cipher = AES128::new(AESMode::CBC, &key("000102030405060708090a0b0c0d0e0f"));
    assert_eq!(cipher.decrypt(&sequence(16), &[], &[0; 24]), Err(AESError::Length));
    assert_eq!(cipher.decrypt(&sequence(16), &[], &[]), Err(AESError::Length));
    let mut ciphertext = cipher.encrypt(&sequence(16), &[], &sequence(16)).unwrap();
    ciphertext[16] ^= 0xff;
    assert_eq!(cipher.decrypt(&sequence(16), &[], &ciphertext), Err(AESError::Padding));
}

#[test]
fn nonce_length() {
    let cipher = AES128::new(AESMode::CBC, &key("000102030405060708090a0b0c0d0e0f"));
    assert_eq!(cipher.encrypt(&sequence(12), &[], &sequence(16)), Err(AESError::Nonce));
    let cipher = AES128::new(AESMode::CCM, &key("000102030405060708090a0b0c0d0e0f"));
    assert_eq!(cipher.encrypt(&sequence(6), &[], &sequence(16)), Err(AESError::Nonce));
    assert_eq!(cipher.encrypt(&sequence(14), &[], &sequence(16)), Err(AESError::Nonce));
}

#[test]
fn expansion() {
    let keys = AES::expand(&hex("2b7e151628aed2a6abf7158809cf4f3c"));
    assert_eq!(keys[1], key::<16>("a0fafe1788542cb123a339392a6c7605"));
    assert_eq!(keys[10], key::<16>("d014f9a8c9ee2589e13f0cc8b6630ca6"));
    let keys = AES::expand(&hex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"));
    assert_eq!(keys[14], key::<16>("fe4890d1e6188d0b046df344706c631e"));
}
