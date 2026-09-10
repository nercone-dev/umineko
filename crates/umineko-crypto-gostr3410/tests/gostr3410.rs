use umineko_crypto_gostr3410::GOSTR3410;

#[test]
fn sizes_follow_rfc7091() {
    let expected = [(GOSTR3410::GC256A, 32), (GOSTR3410::GC256B, 32), (GOSTR3410::GC256C, 32), (GOSTR3410::GC256D, 32), (GOSTR3410::GC512A, 64), (GOSTR3410::GC512B, 64), (GOSTR3410::GC512C, 64)];
    for (variant, coordinate_size) in expected {
        assert_eq!(variant.coordinate_size(), coordinate_size, "{variant}");
        assert_eq!(variant.private_key_size(), coordinate_size, "{variant}");
        assert_eq!(variant.public_key_size(), coordinate_size * 2, "{variant}");
        assert_eq!(variant.signature_size(), coordinate_size * 2, "{variant}");
    }
}

#[test]
fn parameter_sets_follow_rfc9367() {
    let expected = [
        (GOSTR3410::GC256A, "id-tc26-gost-3410-2012-256-paramSetA"),
        (GOSTR3410::GC256B, "id-GostR3410-2001-CryptoPro-A-ParamSet"),
        (GOSTR3410::GC256C, "id-GostR3410-2001-CryptoPro-B-ParamSet"),
        (GOSTR3410::GC256D, "id-GostR3410-2001-CryptoPro-C-ParamSet"),
        (GOSTR3410::GC512A, "id-tc26-gost-3410-12-512-paramSetA"),
        (GOSTR3410::GC512B, "id-tc26-gost-3410-12-512-paramSetB"),
        (GOSTR3410::GC512C, "id-tc26-gost-3410-2012-512-paramSetC"),
    ];
    for (variant, parameter_set) in expected {
        assert_eq!(variant.parameter_set(), parameter_set);
        assert_eq!(GOSTR3410::from_name(variant.as_str()), Some(variant));
    }
}
