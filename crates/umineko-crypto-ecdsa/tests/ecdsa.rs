use umineko_crypto_ecdsa::ECDSA;

#[test]
fn curve_names_follow_sec2_and_rfc7027() {
    let expected = [
        (ECDSA::SECP256R1, "secp256r1"), (ECDSA::SECP384R1, "secp384r1"), (ECDSA::SECP521R1, "secp521r1"), (ECDSA::SECP256K1, "secp256k1"),
        (ECDSA::SECT163K1, "sect163k1"), (ECDSA::SECT163R1, "sect163r1"), (ECDSA::SECT163R2, "sect163r2"), (ECDSA::SECT193R1, "sect193r1"), (ECDSA::SECT193R2, "sect193r2"),
        (ECDSA::SECT233K1, "sect233k1"), (ECDSA::SECT233R1, "sect233r1"), (ECDSA::SECT239K1, "sect239k1"), (ECDSA::SECT283K1, "sect283k1"), (ECDSA::SECT283R1, "sect283r1"),
        (ECDSA::SECT409K1, "sect409k1"), (ECDSA::SECT409R1, "sect409r1"), (ECDSA::SECT571K1, "sect571k1"), (ECDSA::SECT571R1, "sect571r1"),
        (ECDSA::SECP160K1, "secp160k1"), (ECDSA::SECP160R1, "secp160r1"), (ECDSA::SECP160R2, "secp160r2"), (ECDSA::SECP192K1, "secp192k1"), (ECDSA::SECP192R1, "secp192r1"),
        (ECDSA::SECP224K1, "secp224k1"), (ECDSA::SECP224R1, "secp224r1"),
        (ECDSA::BRAINPOOLP256R1, "brainpoolP256r1"), (ECDSA::BRAINPOOLP384R1, "brainpoolP384r1"), (ECDSA::BRAINPOOLP512R1, "brainpoolP512r1"),
    ];
    for (curve, name) in expected {
        assert_eq!(curve.as_str(), name);
        assert_eq!(ECDSA::from_name(name), Some(curve));
    }
}
