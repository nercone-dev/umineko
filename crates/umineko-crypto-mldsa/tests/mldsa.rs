use umineko_crypto_mldsa::{MLDSA, MLDSAError, MLDSAPrivateKey, MLDSAPublicKey, MLDSASignature};
use umineko_hash_sha::SHA3_256;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap()).collect()
}

fn seed() -> Vec<u8> {
    (0..32).map(|_| 0x11).collect()
}

fn message() -> Vec<u8> {
    (0..32).collect()
}

#[test]
fn vectors() {
    for (variant, public, private, signature) in [
        (MLDSA::V44,
         "6b26ea8c0804f6a6bbce358b127bd2642658fda4d6d825b6eb256f6cae2de66c",
         "28ba705bedf5298a1bc9dd9080a9c552cf10fc06ef5756da104607196a425183",
         "229903d9be457a7272e0a5982cc13ebcae9abc8a6626854665de53bbf33c4518"),
        (MLDSA::V65,
         "a163c1528e20de91f7c41aed6c0ec7f3c3a6bc387786ce2196fae49edd93f6c1",
         "51fffcf728434570e2d5bee0d4dfca7431e70c497972969708ecdd19fae9f527",
         "a978bea054a19382c7b6a882976d3eba22fb0a8780c700ebe8eaf8866f14fd7f"),
        (MLDSA::V87,
         "973ac8c977fbfd19070a482bd9871d0cdcd902a728f3b3abcc11072327f48acf",
         "8f89307b5c6d2159efbc6cc9c7d1a46a9cd49cd40150455e6a5e9d253dc846a9",
         "52c6c501f18cf720e5e28641e6eed82549d3d81b918058075eeedeefa91ceee1"),
    ] {
        let (key, verifier) = variant.generate(&seed()).unwrap();
        assert_eq!(verifier.encode().len(), variant.public_key_size(), "{variant}");
        assert_eq!(key.encode().len(), variant.private_key_size(), "{variant}");
        assert_eq!(SHA3_256::digest(&verifier.encode()).to_vec(), hex(public), "{variant}");
        assert_eq!(SHA3_256::digest(&key.encode()).to_vec(), hex(private), "{variant}");
        let produced = key.sign(&message(), &[]).unwrap();
        assert_eq!(produced.encode().len(), variant.signature_size(), "{variant}");
        assert_eq!(SHA3_256::digest(&produced.encode()).to_vec(), hex(signature), "{variant}");
        assert_eq!(verifier.verify(&message(), &produced, &[]), Ok(()), "{variant}");
    }
}

#[test]
fn round_trip() {
    for variant in MLDSA::ALL {
        let (key, verifier) = variant.generate(&seed()).unwrap();
        assert_eq!(key.public_key(), verifier, "{variant}");
        let signature = key.sign(&message(), b"context").unwrap();
        assert_eq!(verifier.verify(&message(), &signature, b"context"), Ok(()), "{variant}");
        assert_eq!(verifier.verify(&message(), &signature, &[]), Err(MLDSAError::Verification), "{variant}");
        assert_eq!(verifier.verify(&message()[..31], &signature, b"context"), Err(MLDSAError::Verification), "{variant}");
        let decoded = MLDSASignature::decode(variant, &signature.encode()).unwrap();
        assert_eq!(verifier.verify(&message(), &decoded, b"context"), Ok(()), "{variant}");
        assert_eq!(MLDSAPrivateKey::decode(variant, &key.encode()).unwrap(), key, "{variant}");
        assert_eq!(MLDSAPublicKey::decode(variant, &verifier.encode()).unwrap(), verifier, "{variant}");
    }
}

#[test]
fn failures() {
    assert_eq!(MLDSA::V65.generate(&[0; 8]).err(), Some(MLDSAError::Seed));
    assert_eq!(MLDSAPrivateKey::decode(MLDSA::V65, &[0; 8]).err(), Some(MLDSAError::Encoding));
    assert_eq!(MLDSAPublicKey::decode(MLDSA::V65, &[0; 8]).err(), Some(MLDSAError::Encoding));
    assert_eq!(MLDSASignature::decode(MLDSA::V65, &[0; 8]).err(), Some(MLDSAError::Encoding));
    let (key, verifier) = MLDSA::V44.generate(&seed()).unwrap();
    assert_eq!(key.sign(&message(), &[0; 256]).err(), Some(MLDSAError::Length));
    let signature = key.sign(&message(), &[]).unwrap();
    assert_eq!(verifier.verify(&message(), &signature, &[0; 256]), Err(MLDSAError::Length));
    let other = MLDSASignature::decode(MLDSA::V65, &[0; 3309]).unwrap();
    assert_eq!(verifier.verify(&message(), &other, &[]), Err(MLDSAError::Variant));
    let empty = MLDSASignature::decode(MLDSA::V44, &[0; 2420]).unwrap();
    assert_eq!(verifier.verify(&message(), &empty, &[]), Err(MLDSAError::Verification));
}
