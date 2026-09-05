use umineko_crypto_ascon::{AsconAEAD128, AsconCXOF128, AsconError, AsconHash256, AsconXOF128};

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
fn hash_vector() {
    assert_eq!(AsconHash256::digest(&[]).to_vec(), hex("0b3be5850f2f6b98caf29f8fdea89b64a1fa70aa249b8f839bd53baa304d92b2"));
}

#[test]
fn hash_streaming() {
    for length in [0, 1, 7, 8, 9, 16, 63, 64] {
        let data = sequence(length);
        let whole = AsconHash256::digest(&data);
        for split in 0..=length {
            let mut hash = AsconHash256::default();
            hash.update(&data[..split]);
            hash.update(&data[split..]);
            assert_eq!(hash.finalize(), whole, "{length} {split}");
        }
        let mut hash = AsconHash256::default();
        hash.update(&data);
        hash.reset();
        hash.update(&data);
        assert_eq!(hash.finalize(), whole, "{length}");
    }
}

#[test]
fn aead_vectors() {
    let cipher = AsconAEAD128::new(&key("000102030405060708090a0b0c0d0e0f"));
    let nonce = key::<16>("101112131415161718191a1b1c1d1e1f");
    for (associated, plaintext, expected) in [
        ("", "", "4f9c278211bec9316bf68f46ee8b2ec6"),
        ("30", "", "cccb674fe18a09a285d6ab11b35675c0"),
        ("3031", "", "f65b191550c4df9cfdd4460ebbcca782"),
        ("303132333435363738393a3b3c3d3e3f", "", "e4230cdb8330ee9dc0cfd7c7b346e6dc"),
        ("303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f", "", "efc3e78b02ad9a80a6f0548c5b0bb5ba"),
        ("", "20", "e8dd576aba1cd3e6fc704de02aedb79588"),
        ("", "202122", "e8c3deaf8e12816b8edf39ad1571a9492b7ca2"),
    ] {
        let ciphertext = cipher.encrypt(&nonce, &hex(associated), &hex(plaintext)).unwrap();
        assert_eq!(ciphertext, hex(expected), "{associated} {plaintext}");
        assert_eq!(cipher.decrypt(&nonce, &hex(associated), &ciphertext).unwrap(), hex(plaintext));
    }
}

#[test]
fn aead_round_trip() {
    let cipher = AsconAEAD128::new(&key("000102030405060708090a0b0c0d0e0f"));
    for length in [0, 1, 15, 16, 17, 32, 100] {
        for associated in [0, 1, 16, 40] {
            let plaintext = sequence(length);
            let extra = sequence(associated);
            let ciphertext = cipher.encrypt(&key("0f0e0d0c0b0a09080706050403020100"), &extra, &plaintext).unwrap();
            assert_eq!(ciphertext.len(), length + AsconAEAD128::TAG_SIZE);
            assert_eq!(cipher.decrypt(&key("0f0e0d0c0b0a09080706050403020100"), &extra, &ciphertext).unwrap(), plaintext, "{length} {associated}");
        }
    }
}

#[test]
fn aead_authentication() {
    let cipher = AsconAEAD128::new(&key("000102030405060708090a0b0c0d0e0f"));
    let mut ciphertext = cipher.encrypt(&[0; 16], &sequence(8), &sequence(32)).unwrap();
    let last = ciphertext.len() - 1;
    ciphertext[last] ^= 1;
    assert_eq!(cipher.decrypt(&[0; 16], &sequence(8), &ciphertext), Err(AsconError::Authentication));
    ciphertext[last] ^= 1;
    assert_eq!(cipher.decrypt(&[0; 16], &sequence(9), &ciphertext), Err(AsconError::Authentication));
    assert_eq!(cipher.decrypt(&[0; 16], &sequence(8), &ciphertext[..8]), Err(AsconError::Length));
}

#[test]
fn extendable_output() {
    let mut short = [0; 32];
    AsconXOF128::digest(&[], &mut short);
    let mut long = [0; 64];
    AsconXOF128::digest(&[], &mut long);
    assert_eq!(short, long[..32]);
    let mut first = [0; 32];
    AsconCXOF128::digest(b"custom", &[], &mut first).unwrap();
    let mut second = [0; 32];
    AsconCXOF128::digest(b"other", &[], &mut second).unwrap();
    assert_ne!(first, second);
    assert_ne!(first, short);
    let mut hash = AsconCXOF128::new(b"custom").unwrap();
    hash.update(&[]);
    let mut third = [0; 32];
    hash.finalize(&mut third);
    assert_eq!(first, third);
    assert!(AsconCXOF128::new(&[0; 257]).is_err());
}
