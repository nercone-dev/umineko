use umineko_crypto_camellia::{Camellia, CamelliaMode, Camellia128, Camellia192, Camellia256};

#[test]
fn parameters_follow_rfc3713() {
    assert_eq!(Camellia::BLOCK_SIZE, 16);
    for (variant, key_size, rounds, constant) in [(Camellia::V128, 16, 18, Camellia128::KEY_SIZE), (Camellia::V192, 24, 24, Camellia192::KEY_SIZE), (Camellia::V256, 32, 24, Camellia256::KEY_SIZE)] {
        assert_eq!(variant.key_size(), key_size, "{variant}");
        assert_eq!(variant.rounds(), rounds, "{variant}");
        assert_eq!(constant, key_size, "{variant}");
        assert_eq!(Camellia::from_name(variant.as_str()), Some(variant));
    }
    assert_eq!((Camellia128::VARIANT, Camellia192::VARIANT, Camellia256::VARIANT), (Camellia::V128, Camellia::V192, Camellia::V256));
}

#[test]
fn provider_names_are_distinct() {
    let modes = [CamelliaMode::ECB, CamelliaMode::CBC, CamelliaMode::CFB, CamelliaMode::OFB, CamelliaMode::CTR, CamelliaMode::GCM, CamelliaMode::CCM, CamelliaMode::CBC_CS3];
    let mut names = Vec::new();
    for variant in [Camellia::V128, Camellia::V192, Camellia::V256] {
        for mode in modes {
            names.push(variant.name(mode));
        }
    }
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 24);
    assert!(CamelliaMode::GCM.authenticated() && CamelliaMode::CCM.authenticated() && !CamelliaMode::CBC.authenticated());
}

#[test]
fn ciphertext_stealing_is_unpadded_by_rfc6803_and_sp800_38a_addendum() {
    assert_eq!(CamelliaMode::CBC_CS3.as_str(), "CBC-CS3");
    assert!(!CamelliaMode::CBC_CS3.padded());
    assert!(!CamelliaMode::CBC_CS3.authenticated());
    assert_eq!(Camellia::V128.name(CamelliaMode::CBC_CS3), "Camellia-128-CBC-CS3");
    assert_eq!(Camellia::V256.name(CamelliaMode::CBC_CS3), "Camellia-256-CBC-CS3");
}
