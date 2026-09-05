use umineko_crypto_mlkem::{MLKEM, MLKEMCiphertext, MLKEMError, MLKEMPrivateKey, MLKEMPublicKey};
use umineko_hash_sha::SHA3_256;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap()).collect()
}

fn seed() -> Vec<u8> {
    let mut seed = alloc_repeat(0x11, 32);
    seed.extend(alloc_repeat(0x22, 32));
    seed
}

fn alloc_repeat(value: u8, length: usize) -> Vec<u8> {
    (0..length).map(|_| value).collect()
}

#[test]
fn vectors() {
    for (variant, public, private, ciphertext, secret) in [
        (MLKEM::V512,
         "57c0d859d49cfd70149736fe36714ab58f264815fd7cdc23610ecd940f62a820",
         "78bfbafecadbe7c87830f43b0a7f81b6997c7a21c10463e3d4e462a214d0bf30",
         "096a94a634a024cbcd87f4034617c32298dfdf8fd1f92e00ae64393d5a223cef",
         "cf286edb4905dae30df31667454dc6024b6332361219ef1a444df2b149c9cf7b"),
        (MLKEM::V768,
         "f1347d50af257fa3e577ed74dfa38736702fd6e2fee25db52ec64f471bd360e7",
         "0d64dbe2dc8cfaeac2cd5bc709e00aa00630acf658d1467766e00fa8a0d48ed4",
         "8de9c83dcfa6f9d0fd668972a395580e5ff3ada2a855edc9937bd970ab25008e",
         "dea5fdd2340a17c7507d1fe5c0609bcba4190e08007d5f7f98c8fecab10bc8fa"),
        (MLKEM::V1024,
         "723a17d314c8fbae88ba58b4046aacfb38196d8a79d4b02296211beb150a97b8",
         "464edc4996bdb25f643246057992cbefc305746c87beec351c4a6716ecb00ea9",
         "fbd7e1f9307242aaec462d987580b3f90d0265fd2d93536efe69d4c3f8e4a0ff",
         "d44bd532fca43fa5943a8be247b35b53e5928ed0cc4105ef4846dd1507c8dd80"),
    ] {
        let (key, encryption) = variant.generate(&seed()).unwrap();
        assert_eq!(encryption.encode().len(), variant.public_key_size(), "{variant}");
        assert_eq!(key.encode().len(), variant.private_key_size(), "{variant}");
        assert_eq!(SHA3_256::digest(&encryption.encode()).to_vec(), hex(public), "{variant}");
        assert_eq!(SHA3_256::digest(&key.encode()).to_vec(), hex(private), "{variant}");
        let (produced, shared) = encryption.encapsulate(&alloc_repeat(0x33, 32)).unwrap();
        assert_eq!(produced.encode().len(), variant.ciphertext_size(), "{variant}");
        assert_eq!(SHA3_256::digest(&produced.encode()).to_vec(), hex(ciphertext), "{variant}");
        assert_eq!(shared.as_slice(), hex(secret), "{variant}");
        assert_eq!(key.decapsulate(&produced).unwrap().as_slice(), hex(secret), "{variant}");
    }
}

#[test]
fn round_trip() {
    for variant in MLKEM::ALL {
        let (key, encryption) = variant.generate(&seed()).unwrap();
        assert_eq!(key.public_key(), encryption, "{variant}");
        let (ciphertext, shared) = encryption.encapsulate(&alloc_repeat(0x44, 32)).unwrap();
        assert_eq!(shared.len(), variant.shared_secret_size(), "{variant}");
        assert!(!shared.is_empty());
        assert_eq!(key.decapsulate(&ciphertext).unwrap(), shared, "{variant}");
        let decoded = MLKEMCiphertext::decode(variant, &ciphertext.encode()).unwrap();
        assert_eq!(key.decapsulate(&decoded).unwrap(), shared, "{variant}");
        assert_eq!(MLKEMPrivateKey::decode(variant, &key.encode()).unwrap(), key, "{variant}");
        assert_eq!(MLKEMPublicKey::decode(variant, &encryption.encode()).unwrap(), encryption, "{variant}");
    }
}

#[test]
fn rejection() {
    for variant in MLKEM::ALL {
        let (key, encryption) = variant.generate(&seed()).unwrap();
        let (ciphertext, shared) = encryption.encapsulate(&alloc_repeat(0x44, 32)).unwrap();
        let mut broken = ciphertext.encode();
        broken[0] ^= 1;
        let broken = MLKEMCiphertext::decode(variant, &broken).unwrap();
        let other = key.decapsulate(&broken).unwrap();
        assert_ne!(other, shared, "{variant}");
        assert_eq!(other.len(), variant.shared_secret_size(), "{variant}");
        assert_eq!(key.decapsulate(&broken).unwrap(), other, "{variant}");
    }
}

#[test]
fn failures() {
    assert_eq!(MLKEM::V768.generate(&[0; 32]).err(), Some(MLKEMError::Seed));
    assert_eq!(MLKEMPrivateKey::decode(MLKEM::V768, &[0; 10]).err(), Some(MLKEMError::Encoding));
    assert_eq!(MLKEMPrivateKey::decode(MLKEM::V768, &[0; 2400]).err(), Some(MLKEMError::Key));
    assert_eq!(MLKEMPublicKey::decode(MLKEM::V768, &[0; 10]).err(), Some(MLKEMError::Encoding));
    assert_eq!(MLKEMPublicKey::decode(MLKEM::V768, &[0xff; 1184]).err(), Some(MLKEMError::Key));
    assert_eq!(MLKEMCiphertext::decode(MLKEM::V768, &[0; 10]).err(), Some(MLKEMError::Encoding));
    let (key, encryption) = MLKEM::V768.generate(&seed()).unwrap();
    assert_eq!(encryption.encapsulate(&[0; 8]).err(), Some(MLKEMError::Seed));
    let (other, _) = MLKEM::V512.generate(&seed()).unwrap();
    let (ciphertext, _) = other.public_key().encapsulate(&alloc_repeat(0x44, 32)).unwrap();
    assert_eq!(key.decapsulate(&ciphertext).err(), Some(MLKEMError::Variant));
}
