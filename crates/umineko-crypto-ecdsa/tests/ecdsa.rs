use umineko_crypto_ecdsa::{ECDSA, ECDSAError, ECDSAPrivateKey, ECDSAPublicKey, ECDSASignature};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap()).collect()
}

#[test]
fn foreign_signatures() {
    for (variant, private, public, digest, signature) in [
        (ECDSA::SECP256R1,
         "020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dc",
         "047218bbf5a90f8d73457ac56cffc5224b60ad71bf85ded935ff782940a18902216f34ce8672b010d96accbf011ed44b713b5fb59a0630dc3e1c0d062f7087c918",
         "630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd",
         "f6b1074c615c3e82fa8b7698dfc6952bdb4cefd355ba238458ed9117dded11fe10a7a70f1af5c1f32ad20a37eb7b676664a055ba765fe2fafa55cb86e3ae58ec"),
        (ECDSA::SECP384R1,
         "020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7030a11181f262d343b424951",
         "04265fa631478ffc4ac6803b674f4f30138e6479bc49ce26d536d5f71200713ebd5e05884ab82365181f8e923935352f00591b1adf47da87e83f922ef7a5817a218420b40d19bf132bdcfaba7bf50845c19ff4cb9a793cb7e66d734e02019f136a",
         "e7112491faeefd57786da73f367b25a6f5769f5c98fa7b704d8d37747724a647371989e8b0fe8d3cb23f9eedd528456b",
         "8df1384fb67481b39111c7dad1ce4e22fda84e70c47955be4eaed236bca85607a3c37b0800798742a54bb652af1ba52e4855ba32e1e76ec5743fba9a3fac87c2895eb2b0cf2ddcf2d7cd2cf0395ae5204591f199c1eaf66775550335fc6429d7"),
        (ECDSA::SECP521R1,
         "000910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2ef9f707b8651e888baad6839f95246b18e29b6a9c1f7ec47e7e234f494288863c7",
         "0400a6cb6a05155c4dfd823186092eb321890185348795de0b02f333bb3d590ff396b3d342e7beb243c11ff37c926b57c7c4f097f9906559ea3aa1101a039f1a07759b01543f442664fabd722f21be4d3cbf171fc1426d7016b71962e697976d663d9a8c88f6f0f15cc01639d91edf66e8b29bf052e461a50ddca873fd69da68a50786c3ef",
         "3d94eea49c580aef816935762be049559d6d1440dede12e6a125f1841fff8e6fa9d71862a3e5746b571be3d187b0041046f52ebd850c7cbd5fde8ee38473b649",
         "01c66eb785e1ae28a3d6b8cdf52a795e746701fd1e2038b785fa67fa3b087fb3b250074803db9d97ecb3ef1439d30c1c140000e7da770872f0289a1a423f313b60dc007ae9445153059ee58439b0cad95988537a5443617776834af7bcceddaf1bbc610fdd016bb00e279bd8b2345531cf09529ec1a5e166792f989920ff8fcaad355df6"),
    ] {
        let key = ECDSAPrivateKey::decode(variant, &hex(private)).unwrap();
        assert_eq!(key.public_key().encode(), hex(public), "{variant}");
        let public = ECDSAPublicKey::decode(variant, &hex(public)).unwrap();
        let signature = ECDSASignature::decode(variant, &hex(signature)).unwrap();
        assert_eq!(public.verify(&hex(digest), &signature), Ok(()), "{variant}");
        let mut broken = hex(digest);
        broken[0] ^= 1;
        assert_eq!(public.verify(&broken, &signature), Err(ECDSAError::Verification), "{variant}");
    }
}

#[test]
fn deterministic_signature() {
    let key = ECDSAPrivateKey::decode(ECDSA::SECP256R1, &hex("020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dc")).unwrap();
    let digest = hex("630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd");
    let signature = key.sign(&digest).unwrap();
    assert_eq!(signature.encode(), hex("e9bcf7aa1f1165c60e22abe664c834405177da9eef7f154c4b74af59c803c1ff8c4330bc486c0cbbfc65f74021bb73d7b6c48bec5ec8d3b330a300066ead8096"));
    assert_eq!(key.public_key().verify(&digest, &signature), Ok(()));
}

#[test]
fn round_trip() {
    for variant in ECDSA::ALL {
        let (private, public) = variant.generate(&[0x5a; 66]).unwrap();
        assert_eq!(public.encode().len(), variant.public_key_size(), "{variant}");
        let digest: Vec<u8> = (0..32).collect();
        let signature = private.sign(&digest).unwrap();
        assert_eq!(signature.encode().len(), variant.signature_size(), "{variant}");
        assert_eq!(public.verify(&digest, &signature), Ok(()), "{variant}");
        assert_eq!(private.sign(&digest).unwrap(), signature, "{variant}");
        let other: Vec<u8> = (1..33).collect();
        assert_eq!(public.verify(&other, &signature), Err(ECDSAError::Verification), "{variant}");
        let decoded = ECDSASignature::decode(variant, &signature.encode()).unwrap();
        assert_eq!(public.verify(&digest, &decoded), Ok(()), "{variant}");
        assert_eq!(ECDSAPublicKey::decode(variant, &public.encode()).unwrap(), public, "{variant}");
    }
}

#[test]
fn failures() {
    assert_eq!(ECDSA::SECP256R1.generate(&[0; 8]).err(), Some(ECDSAError::Seed));
    assert_eq!(ECDSAPrivateKey::decode(ECDSA::SECP256R1, &[0; 31]).err(), Some(ECDSAError::Encoding));
    assert_eq!(ECDSAPrivateKey::decode(ECDSA::SECP256R1, &[0; 32]).err(), Some(ECDSAError::Key));
    assert_eq!(ECDSASignature::decode(ECDSA::SECP256R1, &[0; 63]).err(), Some(ECDSAError::Length));
    assert_eq!(ECDSAPublicKey::decode(ECDSA::SECP256R1, &[4; 65]).err(), Some(ECDSAError::Encoding));
    let (_, public) = ECDSA::SECP256R1.generate(&[0x5a; 32]).unwrap();
    let zero = ECDSASignature::decode(ECDSA::SECP256R1, &[0; 64]).unwrap();
    assert_eq!(public.verify(&[0; 32], &zero), Err(ECDSAError::Verification));
    let (_, other) = ECDSA::SECP384R1.generate(&[0x5a; 48]).unwrap();
    let signature = ECDSASignature::decode(ECDSA::SECP384R1, &[1; 96]).unwrap();
    assert_eq!(public.verify(&[0; 32], &signature), Err(ECDSAError::Variant));
    assert_eq!(other.verify(&[0; 48], &signature), Err(ECDSAError::Verification));
}
