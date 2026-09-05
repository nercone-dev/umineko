use umineko_crypto_ecdh::{ECDH, ECDHError, ECDHPrivateKey, ECDHPublicKey};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap()).collect()
}

#[test]
fn ladder_vectors() {
    let private = ECDHPrivateKey::decode(ECDH::X25519, &hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")).unwrap();
    assert_eq!(private.public_key().encode(), hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
    let peer = ECDHPublicKey::decode(ECDH::X25519, &hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")).unwrap();
    assert_eq!(private.exchange(&peer).unwrap().as_slice(), hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"));
    let private = ECDHPrivateKey::decode(ECDH::X448, &hex("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b")).unwrap();
    assert_eq!(private.public_key().encode(), hex("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"));
}

#[test]
fn curve_vectors() {
    for (curve, private, public, peer, shared) in [
        (ECDH::SECP256R1,
         "020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dc",
         "047218bbf5a90f8d73457ac56cffc5224b60ad71bf85ded935ff782940a18902216f34ce8672b010d96accbf011ed44b713b5fb59a0630dc3e1c0d062f7087c918",
         "044c872b45d7e859a0ebf75f9f23d50e6f97a686c009c47234930ff0acb4297732c0f5f6ea9ff60a9583340c05414db1599ca267d6c02cb43253e97962bd0da704",
         "2333e7579eef88b0867fe8c109a94c231d6c5165030c8406aa7ec661b6cd076b"),
        (ECDH::SECP384R1,
         "020910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2e9f0f7030a11181f262d343b424951",
         "04265fa631478ffc4ac6803b674f4f30138e6479bc49ce26d536d5f71200713ebd5e05884ab82365181f8e923935352f00591b1adf47da87e83f922ef7a5817a218420b40d19bf132bdcfaba7bf50845c19ff4cb9a793cb7e66d734e02019f136a",
         "04e30c4f9f25f942324961c46714ed4cec04e16cdb21cad6df42241519128818491061baceeb954971240c549a980c78d30a45b06fb033b8330a4b17406161ce478b213f36c6d2100bafe6f91703f2c978bcb03e8b87dabb80d76bb91faaabc3f0",
         "d3b139d03a073830d3f9774e0a6095dd29326fe1d0874cbf880deeb94c5b9c277a23e1909d3a21e85f04c4aeae6d61b4"),
        (ECDH::SECP521R1,
         "000910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2ef9f707b8651e888baad6839f95246b18e29b6a9c1f7ec47e7e234f494288863c7",
         "0400a6cb6a05155c4dfd823186092eb321890185348795de0b02f333bb3d590ff396b3d342e7beb243c11ff37c926b57c7c4f097f9906559ea3aa1101a039f1a07759b01543f442664fabd722f21be4d3cbf171fc1426d7016b71962e697976d663d9a8c88f6f0f15cc01639d91edf66e8b29bf052e461a50ddca873fd69da68a50786c3ef",
         "040073eb30477b67bba0886c1997ccb1290d3b1523e37d4da4c3caef61f4511e2482609d58fd17ba91e5b4e6a8a104aabdd9e13e2295664722accf84f49dc950a9c58101e076902d2de8afc4fd283a2230a0a980ba14e5d48bbe5e434b279068ebb4db3358dfb25d806a196b493e1a7922bac9a8533ef9e2d8cd920fa2c20becca4e2ec2c1",
         "004009f0b9821222ff93597280dbe3b954d84fc511aee4705f1a60a90c05dc60399e795f44ecd09aa6c5f3422aabcfc694fa8273007d19f122a03fa175ebde705390"),
    ] {
        let private = ECDHPrivateKey::decode(curve, &hex(private)).unwrap();
        assert_eq!(private.public_key().encode(), hex(public), "{curve}");
        let peer = ECDHPublicKey::decode(curve, &hex(peer)).unwrap();
        assert_eq!(private.exchange(&peer).unwrap().as_slice(), hex(shared), "{curve}");
    }
}

#[test]
fn agreement() {
    for curve in ECDH::ALL {
        let (first, first_public) = curve.generate(&[0x11; 66]).unwrap();
        let (second, second_public) = curve.generate(&[0x22; 66]).unwrap();
        assert_eq!(first_public.encode().len(), curve.public_key_size(), "{curve}");
        assert_eq!(first.encode().len(), curve.private_key_size(), "{curve}");
        let left = first.exchange(&second_public).unwrap();
        let right = second.exchange(&first_public).unwrap();
        assert_eq!(left.as_slice(), right.as_slice(), "{curve}");
        assert_eq!(left.len(), curve.shared_secret_size(), "{curve}");
        assert!(!left.is_empty());
        let decoded = ECDHPublicKey::decode(curve, &first_public.encode()).unwrap();
        assert_eq!(decoded.encode(), first_public.encode(), "{curve}");
        assert_eq!(ECDHPrivateKey::decode(curve, &first.encode()).unwrap(), first, "{curve}");
    }
}

#[test]
fn failures() {
    assert_eq!(ECDH::SECP256R1.generate(&[0; 8]).err(), Some(ECDHError::Seed));
    assert_eq!(ECDHPrivateKey::decode(ECDH::SECP256R1, &[0; 31]).err(), Some(ECDHError::Encoding));
    assert_eq!(ECDHPrivateKey::decode(ECDH::SECP256R1, &[0; 32]).err(), Some(ECDHError::Key));
    assert_eq!(ECDHPublicKey::decode(ECDH::SECP256R1, &[4; 65]).err(), Some(ECDHError::Point));
    assert_eq!(ECDHPublicKey::decode(ECDH::X25519, &[0; 31]).err(), Some(ECDHError::Encoding));
    let (private, _) = ECDH::SECP256R1.generate(&[0x33; 32]).unwrap();
    let (_, other) = ECDH::SECP384R1.generate(&[0x33; 48]).unwrap();
    assert_eq!(private.exchange(&other).err(), Some(ECDHError::Curve));
    let (private, _) = ECDH::X25519.generate(&[0x33; 32]).unwrap();
    let zero = ECDHPublicKey::decode(ECDH::X25519, &[0; 32]).unwrap();
    assert_eq!(private.exchange(&zero).err(), Some(ECDHError::SharedSecret));
}
