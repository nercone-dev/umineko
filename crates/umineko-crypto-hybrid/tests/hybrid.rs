use umineko_crypto_hybrid::{HybridKEX, HybridKEXCiphertext, HybridKEXError, HybridKEXPrivateKey, HybridKEXPublicKey};

fn seed(value: u8, length: usize) -> Vec<u8> {
    (0..length).map(|index| value.wrapping_add(index as u8)).collect()
}

#[test]
fn sizes() {
    assert_eq!(HybridKEX::X25519MLKEM768.public_key_size(), 1216);
    assert_eq!(HybridKEX::X25519MLKEM768.ciphertext_size(), 1120);
    assert_eq!(HybridKEX::X25519MLKEM768.shared_secret_size(), 64);
    assert_eq!(HybridKEX::SECP256R1MLKEM768.public_key_size(), 1249);
    assert_eq!(HybridKEX::SECP256R1MLKEM768.ciphertext_size(), 1153);
    assert_eq!(HybridKEX::SECP384R1MLKEM1024.public_key_size(), 1665);
    assert_eq!(HybridKEX::SECP384R1MLKEM1024.shared_secret_size(), 80);
    assert!(HybridKEX::X25519MLKEM768.lattice_first());
    assert!(!HybridKEX::SECP256R1MLKEM768.lattice_first());
    assert_eq!(HybridKEX::from_name("X25519MLKEM768"), Some(HybridKEX::X25519MLKEM768));
    assert_eq!(HybridKEX::from_name("nothing"), None);
}

#[test]
fn agreement() {
    for variant in HybridKEX::ALL {
        let (private, public) = variant.generate(&seed(0x11, variant.seed_size())).unwrap();
        assert_eq!(public.encode().len(), variant.public_key_size(), "{variant}");
        assert_eq!(private.encode().len(), variant.private_key_size(), "{variant}");
        assert_eq!(private.public_key(), public, "{variant}");
        let (ciphertext, secret) = public.encapsulate(&seed(0x22, variant.seed_size())).unwrap();
        assert_eq!(ciphertext.encode().len(), variant.ciphertext_size(), "{variant}");
        assert_eq!(secret.len(), variant.shared_secret_size(), "{variant}");
        assert!(!secret.is_empty());
        assert_eq!(private.decapsulate(&ciphertext).unwrap(), secret, "{variant}");
        let decoded = HybridKEXCiphertext::decode(variant, &ciphertext.encode()).unwrap();
        assert_eq!(private.decapsulate(&decoded).unwrap(), secret, "{variant}");
        assert_eq!(HybridKEXPrivateKey::decode(variant, &private.encode()).unwrap(), private, "{variant}");
        assert_eq!(HybridKEXPublicKey::decode(variant, &public.encode()).unwrap(), public, "{variant}");
    }
}

#[test]
fn halves() {
    let variant = HybridKEX::X25519MLKEM768;
    let (_, public) = variant.generate(&seed(0x11, variant.seed_size())).unwrap();
    let encoded = public.encode();
    assert_eq!(&encoded[..variant.mlkem().public_key_size()], &encoded[..1184]);
    let variant = HybridKEX::SECP256R1MLKEM768;
    let (_, public) = variant.generate(&seed(0x11, variant.seed_size())).unwrap();
    assert_eq!(public.encode()[0], 4);
}

#[test]
fn failures() {
    let variant = HybridKEX::X25519MLKEM768;
    assert_eq!(variant.generate(&[0; 8]).err(), Some(HybridKEXError::Length));
    assert_eq!(HybridKEXPrivateKey::decode(variant, &[0; 8]).err(), Some(HybridKEXError::Length));
    assert_eq!(HybridKEXPublicKey::decode(variant, &[0; 8]).err(), Some(HybridKEXError::Length));
    assert_eq!(HybridKEXCiphertext::decode(variant, &[0; 8]).err(), Some(HybridKEXError::Length));
    let (private, public) = variant.generate(&seed(0x11, variant.seed_size())).unwrap();
    assert_eq!(public.encapsulate(&[0; 8]).err(), Some(HybridKEXError::Length));
    let other = HybridKEX::SECP256R1MLKEM768;
    let (_, second) = other.generate(&seed(0x11, other.seed_size())).unwrap();
    let (ciphertext, _) = second.encapsulate(&seed(0x22, other.seed_size())).unwrap();
    assert_eq!(private.decapsulate(&ciphertext).err(), Some(HybridKEXError::Variant));
}
