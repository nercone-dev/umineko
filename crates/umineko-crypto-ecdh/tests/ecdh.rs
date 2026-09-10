use umineko_crypto_ecdh::{ECDH, ECDHCurve};

#[test]
fn curve_names_follow_sec2_rfc7748_rfc7027_rfc9367_and_rfc8998() {
    let expected = [
        (ECDHCurve::X25519, "X25519"), (ECDHCurve::X448, "X448"),
        (ECDHCurve::SECP256R1, "secp256r1"), (ECDHCurve::SECP384R1, "secp384r1"), (ECDHCurve::SECP521R1, "secp521r1"),
        (ECDHCurve::SECT163K1, "sect163k1"), (ECDHCurve::SECT163R1, "sect163r1"), (ECDHCurve::SECT163R2, "sect163r2"), (ECDHCurve::SECT193R1, "sect193r1"), (ECDHCurve::SECT193R2, "sect193r2"),
        (ECDHCurve::SECT233K1, "sect233k1"), (ECDHCurve::SECT233R1, "sect233r1"), (ECDHCurve::SECT239K1, "sect239k1"), (ECDHCurve::SECT283K1, "sect283k1"), (ECDHCurve::SECT283R1, "sect283r1"),
        (ECDHCurve::SECT409K1, "sect409k1"), (ECDHCurve::SECT409R1, "sect409r1"), (ECDHCurve::SECT571K1, "sect571k1"), (ECDHCurve::SECT571R1, "sect571r1"),
        (ECDHCurve::SECP160K1, "secp160k1"), (ECDHCurve::SECP160R1, "secp160r1"), (ECDHCurve::SECP160R2, "secp160r2"), (ECDHCurve::SECP192K1, "secp192k1"), (ECDHCurve::SECP192R1, "secp192r1"),
        (ECDHCurve::SECP224K1, "secp224k1"), (ECDHCurve::SECP224R1, "secp224r1"), (ECDHCurve::SECP256K1, "secp256k1"),
        (ECDHCurve::BRAINPOOLP256R1, "brainpoolP256r1"), (ECDHCurve::BRAINPOOLP384R1, "brainpoolP384r1"), (ECDHCurve::BRAINPOOLP512R1, "brainpoolP512r1"),
        (ECDHCurve::GC256A, "GC256A"), (ECDHCurve::GC256B, "GC256B"), (ECDHCurve::GC256C, "GC256C"), (ECDHCurve::GC256D, "GC256D"), (ECDHCurve::GC512A, "GC512A"), (ECDHCurve::GC512B, "GC512B"), (ECDHCurve::GC512C, "GC512C"),
        (ECDHCurve::SM2P256V1, "sm2p256v1"),
    ];
    for (curve, name) in expected {
        assert_eq!(curve.as_str(), name);
        assert_eq!(ECDHCurve::from_name(name), Some(curve));
        assert_eq!(ECDH::Curve(curve).request().algorithm, name);
        assert_eq!(ECDH::Curve(curve).request().parameters, None);
    }
}

#[test]
fn field_sizes_follow_sec2_rfc7748_rfc5639_rfc7091_and_gbt32918() {
    let expected = [
        (ECDHCurve::X25519, 255), (ECDHCurve::X448, 448),
        (ECDHCurve::SECP256R1, 256), (ECDHCurve::SECP384R1, 384), (ECDHCurve::SECP521R1, 521),
        (ECDHCurve::SECT163K1, 163), (ECDHCurve::SECT163R1, 163), (ECDHCurve::SECT163R2, 163), (ECDHCurve::SECT193R1, 193), (ECDHCurve::SECT193R2, 193),
        (ECDHCurve::SECT233K1, 233), (ECDHCurve::SECT233R1, 233), (ECDHCurve::SECT239K1, 239), (ECDHCurve::SECT283K1, 283), (ECDHCurve::SECT283R1, 283),
        (ECDHCurve::SECT409K1, 409), (ECDHCurve::SECT409R1, 409), (ECDHCurve::SECT571K1, 571), (ECDHCurve::SECT571R1, 571),
        (ECDHCurve::SECP160K1, 160), (ECDHCurve::SECP160R1, 160), (ECDHCurve::SECP160R2, 160), (ECDHCurve::SECP192K1, 192), (ECDHCurve::SECP192R1, 192),
        (ECDHCurve::SECP224K1, 224), (ECDHCurve::SECP224R1, 224), (ECDHCurve::SECP256K1, 256),
        (ECDHCurve::BRAINPOOLP256R1, 256), (ECDHCurve::BRAINPOOLP384R1, 384), (ECDHCurve::BRAINPOOLP512R1, 512),
        (ECDHCurve::GC256A, 256), (ECDHCurve::GC256B, 256), (ECDHCurve::GC256C, 256), (ECDHCurve::GC256D, 256), (ECDHCurve::GC512A, 512), (ECDHCurve::GC512B, 512), (ECDHCurve::GC512C, 512),
        (ECDHCurve::SM2P256V1, 256),
    ];
    for (curve, bits) in expected {
        assert_eq!(curve.bits(), bits, "{curve}");
        assert_eq!(ECDH::Curve(curve).bits(), bits, "{curve}");
    }
}

#[test]
fn explicit_domains_are_requested_by_the_generic_algorithm_name() {
    assert_eq!(ECDH::NAME, "ECDH");
    assert_eq!(ECDHCurve::from_name(ECDH::NAME), None);
}
