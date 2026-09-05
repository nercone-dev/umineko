use umineko_crypto_eddsa::{EdDSA, EdDSAError, EdDSAPrivateKey, EdDSAPublicKey, EdDSASignature};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap()).collect()
}

#[test]
fn edwards25519_vectors() {
    for (private, public, message, signature) in [
        ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
         "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
         "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
        ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
         "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
         "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ] {
        let key = EdDSAPrivateKey::decode(EdDSA::Ed25519, &hex(private)).unwrap();
        assert_eq!(key.public_key().encode(), hex(public), "{message}");
        let produced = key.sign(&hex(message), &[]).unwrap();
        assert_eq!(produced.encode(), hex(signature), "{message}");
        let public = EdDSAPublicKey::decode(EdDSA::Ed25519, &hex(public)).unwrap();
        assert_eq!(public.verify(&hex(message), &produced, &[]), Ok(()), "{message}");
    }
}

#[test]
fn edwards448_vectors() {
    let private = "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b";
    let public = "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180";
    let signature = "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600";
    let key = EdDSAPrivateKey::decode(EdDSA::Ed448, &hex(private)).unwrap();
    assert_eq!(key.public_key().encode(), hex(public));
    let produced = key.sign(&[], &[]).unwrap();
    assert_eq!(produced.encode(), hex(signature));
    let public = EdDSAPublicKey::decode(EdDSA::Ed448, &hex(public)).unwrap();
    assert_eq!(public.verify(&[], &produced, &[]), Ok(()));
}

#[test]
fn context_vector() {
    let private = "0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6";
    let public = "dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292";
    let message = "f726936d19c800494e3fdaff20b276a8";
    let context = "666f6f";
    let signature = "55a4cc2f70a54e04288c5f4cd1e45a7bb520b36292911876cada7323198dd87a8b36950b95130022907a7fb7c4e9b2d5f6cca685a587b4b21f4b888e4e7edb0d";
    let key = EdDSAPrivateKey::decode(EdDSA::Ed25519, &hex(private)).unwrap();
    assert_eq!(key.public_key().encode(), hex(public));
    let produced = key.sign(&hex(message), &hex(context)).unwrap();
    assert_eq!(produced.encode(), hex(signature));
    let public = EdDSAPublicKey::decode(EdDSA::Ed25519, &hex(public)).unwrap();
    assert_eq!(public.verify(&hex(message), &produced, &hex(context)), Ok(()));
    assert_eq!(public.verify(&hex(message), &produced, &[]), Err(EdDSAError::Verification));
}

#[test]
fn round_trip() {
    for variant in EdDSA::ALL {
        let (private, public) = variant.generate(&[0x7f; 57]).unwrap();
        assert_eq!(public.encode().len(), variant.public_key_size(), "{variant}");
        let message: Vec<u8> = (0..100).collect();
        let signature = private.sign(&message, b"context").unwrap();
        assert_eq!(signature.encode().len(), variant.signature_size(), "{variant}");
        assert_eq!(public.verify(&message, &signature, b"context"), Ok(()), "{variant}");
        assert_eq!(public.verify(&message[..99], &signature, b"context"), Err(EdDSAError::Verification), "{variant}");
        let decoded = EdDSASignature::decode(variant, &signature.encode()).unwrap();
        assert_eq!(public.verify(&message, &decoded, b"context"), Ok(()), "{variant}");
        assert_eq!(EdDSAPublicKey::decode(variant, &public.encode()).unwrap(), public, "{variant}");
    }
}

#[test]
fn failures() {
    assert_eq!(EdDSA::Ed25519.generate(&[0; 8]).err(), Some(EdDSAError::Seed));
    assert_eq!(EdDSAPrivateKey::decode(EdDSA::Ed25519, &[0; 31]).err(), Some(EdDSAError::Encoding));
    assert_eq!(EdDSAPublicKey::decode(EdDSA::Ed25519, &[0; 31]).err(), Some(EdDSAError::Encoding));
    assert_eq!(EdDSASignature::decode(EdDSA::Ed25519, &[0; 63]).err(), Some(EdDSAError::Length));
    let (private, public) = EdDSA::Ed25519.generate(&[0x7f; 32]).unwrap();
    assert_eq!(private.sign(&[], &[0; 256]).err(), Some(EdDSAError::Length));
    let signature = private.sign(b"message", &[]).unwrap();
    assert_eq!(public.verify(b"message", &signature, &[0; 256]), Err(EdDSAError::Length));
    let other = EdDSASignature::decode(EdDSA::Ed448, &[0; 114]).unwrap();
    assert_eq!(public.verify(b"message", &other, &[]), Err(EdDSAError::Variant));
}
