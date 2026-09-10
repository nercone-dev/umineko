use umineko_crypto_aria::{ARIA, ARIAMode, ARIA128, ARIA192, ARIA256};

#[test]
fn parameters_follow_rfc5794() {
    assert_eq!(ARIA::BLOCK_SIZE, 16);
    for (variant, key_size, rounds, constant) in [(ARIA::V128, 16, 12, ARIA128::KEY_SIZE), (ARIA::V192, 24, 14, ARIA192::KEY_SIZE), (ARIA::V256, 32, 16, ARIA256::KEY_SIZE)] {
        assert_eq!(variant.key_size(), key_size, "{variant}");
        assert_eq!(variant.rounds(), rounds, "{variant}");
        assert_eq!(constant, key_size, "{variant}");
        assert_eq!(ARIA::from_name(variant.as_str()), Some(variant));
    }
}

#[test]
fn provider_names_are_distinct() {
    let modes = [ARIAMode::ECB, ARIAMode::CBC, ARIAMode::CFB, ARIAMode::OFB, ARIAMode::CTR, ARIAMode::GCM];
    let mut names = Vec::new();
    for variant in [ARIA::V128, ARIA::V192, ARIA::V256] {
        for mode in modes {
            names.push(variant.name(mode));
        }
    }
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 18);
}
