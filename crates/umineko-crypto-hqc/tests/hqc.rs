mod data;

use umineko_crypto_hqc::{HQC, HQCCiphertext, HQCError, HQCPrivateKey, HQCPublicKey};
use umineko_hash_sha::SHA3_256;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap()).collect()
}

fn joined(parts: &[&str]) -> Vec<u8> {
    hex(&parts.concat())
}

fn seed(variant: HQC) -> Vec<u8> {
    (0..32).map(|index| (index * 3 + 1) as u8).take(variant.seed_size()).collect()
}

fn material(variant: HQC) -> Vec<u8> {
    (0..variant.message_size() + 16).map(|index| index as u8).collect()
}

/// One key pair and one ciphertext of another implementation, which must open the same way here.
#[test]
fn foreign_key() {
    let variant = HQC::V128;
    let key = HQCPrivateKey::decode(variant, &joined(&data::PRIVATE_KEY)).unwrap();
    assert_eq!(key.public_key().encode(), joined(&data::PUBLIC_KEY));
    let ciphertext = HQCCiphertext::decode(variant, &joined(&data::CIPHERTEXT)).unwrap();
    assert_eq!(key.decapsulate(&ciphertext).unwrap().as_slice(), joined(&data::SHARED_SECRET));
    let public = HQCPublicKey::decode(variant, &joined(&data::PUBLIC_KEY)).unwrap();
    let (produced, secret) = public.encapsulate(&material(variant)).unwrap();
    assert_eq!(produced.encode().len(), variant.ciphertext_size());
    assert_eq!(secret.len(), variant.shared_secret_size());
    assert_ne!(produced.encode(), ciphertext.encode());
}

#[test]
fn vectors() {
    for (variant, public, private, ciphertext, secret) in [
        (HQC::V128,
         "2b26d3e1fc5cd7667733cac3c0434dc23fdd2361f8a1d2279b81bf5ee060adbf",
         "8c5aea4fe96ee68cccaf92f12acf67467390fe1ca44f500211b54e7419827b4c",
         "45b80f3f255e5fa96031fc04ff9fe78e168c9fb29aeb53f873211cc9eaea3f19",
         "b28a5685810db854502c2439bd0c121eab2697a0c76ef68414ba634d326ed063"),
        (HQC::V192,
         "8f0ec25a21cddcbc347681945019659ed360b423fb80befe11f2015285646c12",
         "9e433f66c6b9e9e742a8ede25b68250d785c6c8f7a3af23853a7e056f1471811",
         "ccde1a584ffe0186e67c79ee2fbab093699c74fb03284ff39ebf75a4b1de789b",
         "9a996e537046d5da8fdf945cddbf81e04d5ed8d5f2e08d37049cc8e1ac3dc23a"),
        (HQC::V256,
         "dd05ca15aeb0ae4a6d89211b88e77ea25354a80d110999e1949c059fd092b149",
         "a4bedce61305642266804029f6363571e8a8c69b3e00087852c70769b3e8c69d",
         "11c47e4736da128ccccc45d30e842ed4f6a19be0e14d7ef8adfd5e1f1c4bd53f",
         "f849e1d2c4131ad81b45ed78370801af56ee63fc151182b2583fa09e7d4b6394"),
    ] {
        let (key, verifier) = variant.generate(&seed(variant)).unwrap();
        assert_eq!(verifier.encode().len(), variant.public_key_size(), "{variant}");
        assert_eq!(key.encode().len(), variant.private_key_size(), "{variant}");
        assert_eq!(SHA3_256::digest(&verifier.encode()).to_vec(), hex(public), "{variant}");
        assert_eq!(SHA3_256::digest(&key.encode()).to_vec(), hex(private), "{variant}");
        let (produced, shared) = verifier.encapsulate(&material(variant)).unwrap();
        assert_eq!(produced.encode().len(), variant.ciphertext_size(), "{variant}");
        assert_eq!(SHA3_256::digest(&produced.encode()).to_vec(), hex(ciphertext), "{variant}");
        assert_eq!(shared.as_slice(), hex(secret), "{variant}");
        assert_eq!(key.decapsulate(&produced).unwrap().as_slice(), hex(secret), "{variant}");
    }
}

#[test]
fn round_trip() {
    for variant in HQC::ALL {
        let (key, verifier) = variant.generate(&seed(variant)).unwrap();
        assert_eq!(key.public_key(), verifier, "{variant}");
        let (ciphertext, shared) = verifier.encapsulate(&material(variant)).unwrap();
        assert_eq!(key.decapsulate(&ciphertext).unwrap(), shared, "{variant}");
        let decoded = HQCCiphertext::decode(variant, &ciphertext.encode()).unwrap();
        assert_eq!(key.decapsulate(&decoded).unwrap(), shared, "{variant}");
        assert_eq!(HQCPrivateKey::decode(variant, &key.encode()).unwrap(), key, "{variant}");
        assert_eq!(HQCPublicKey::decode(variant, &verifier.encode()).unwrap(), verifier, "{variant}");
    }
}

#[test]
fn rejection() {
    for variant in HQC::ALL {
        let (key, verifier) = variant.generate(&seed(variant)).unwrap();
        let (ciphertext, shared) = verifier.encapsulate(&material(variant)).unwrap();
        let mut broken = ciphertext.encode();
        let last = broken.len() - 1;
        broken[last] ^= 1;
        let broken = HQCCiphertext::decode(variant, &broken).unwrap();
        let other = key.decapsulate(&broken).unwrap();
        assert_ne!(other, shared, "{variant}");
        assert_eq!(other.len(), variant.shared_secret_size(), "{variant}");
        assert_eq!(key.decapsulate(&broken).unwrap(), other, "{variant}");
    }
}

#[test]
fn failures() {
    let variant = HQC::V128;
    assert_eq!(variant.generate(&[0; 8]).err(), Some(HQCError::Seed));
    assert_eq!(HQCPrivateKey::decode(variant, &[0; 8]).err(), Some(HQCError::Encoding));
    assert_eq!(HQCPublicKey::decode(variant, &[0; 8]).err(), Some(HQCError::Encoding));
    assert_eq!(HQCCiphertext::decode(variant, &[0; 8]).err(), Some(HQCError::Encoding));
    let (key, verifier) = variant.generate(&seed(variant)).unwrap();
    assert_eq!(verifier.encapsulate(&[0; 8]).err(), Some(HQCError::Seed));
    let (other, _) = HQC::V192.generate(&seed(HQC::V192)).unwrap();
    let (ciphertext, _) = other.public_key().encapsulate(&material(HQC::V192)).unwrap();
    assert_eq!(key.decapsulate(&ciphertext).err(), Some(HQCError::Variant));
    assert_eq!(HQC::from_name("HQC-128"), Some(HQC::V128));
    assert_eq!(HQC::from_name("nothing"), None);
}
