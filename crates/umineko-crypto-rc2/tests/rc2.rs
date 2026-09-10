use umineko_crypto_rc2::{RC2, RC2Error, RC2Mode, RC2Variant};

#[test]
fn keys_between_1_and_128_bytes_are_accepted_by_rfc2268() {
    assert_eq!(RC2::BLOCK_SIZE, 8);
    assert_eq!(RC2::new(RC2Mode::CBC, RC2Variant::V40, &[]).unwrap_err(), RC2Error::Key);
    assert!(RC2::new(RC2Mode::CBC, RC2Variant::V40, &[0; 1]).is_ok());
    assert!(RC2::new(RC2Mode::CBC, RC2Variant::V128, &[0; 128]).is_ok());
    assert_eq!(RC2::new(RC2Mode::CBC, RC2Variant::V128, &[0; 129]).unwrap_err(), RC2Error::Key);
}

#[test]
fn variants_describe_the_effective_key_bits() {
    let mut names = Vec::new();
    for (variant, bits) in [(RC2Variant::V40, 40), (RC2Variant::V64, 64), (RC2Variant::V128, 128)] {
        assert_eq!(variant.effective_bits(), bits);
        assert_eq!(RC2Variant::from_name(variant.as_str()), Some(variant));
        for mode in [RC2Mode::ECB, RC2Mode::CBC] {
            names.push(variant.name(mode));
        }
    }
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 6);
}
