use umineko_crypto_aes::{AES, AESMode, AES128, AES192, AES256};

const MODES: [AESMode; 9] = [AESMode::ECB, AESMode::CBC, AESMode::CFB, AESMode::OFB, AESMode::CTR, AESMode::GCM, AESMode::CCM, AESMode::CCM8, AESMode::CBC_CS3];

#[test]
fn parameters_follow_fips197() {
    assert_eq!(AES::BLOCK_SIZE, 16);
    for (variant, key_size, rounds, constant) in [(AES::V128, 16, 10, AES128::KEY_SIZE), (AES::V192, 24, 12, AES192::KEY_SIZE), (AES::V256, 32, 14, AES256::KEY_SIZE)] {
        assert_eq!(variant.key_size(), key_size, "{variant}");
        assert_eq!(variant.rounds(), rounds, "{variant}");
        assert_eq!(constant, key_size, "{variant}");
        assert_eq!(AES::from_name(variant.as_str()), Some(variant));
    }
    assert_eq!((AES128::BLOCK_SIZE, AES192::BLOCK_SIZE, AES256::BLOCK_SIZE), (16, 16, 16));
    assert_eq!((AES128::VARIANT, AES192::VARIANT, AES256::VARIANT), (AES::V128, AES::V192, AES::V256));
}

#[test]
fn provider_names_are_distinct() {
    let mut names = Vec::new();
    for variant in [AES::V128, AES::V192, AES::V256] {
        for mode in MODES {
            let name = variant.name(mode);
            assert!(name.starts_with(variant.as_str()) && name.ends_with(mode.as_str()), "{name}");
            names.push(name);
        }
    }
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 27);
}

#[test]
fn only_gcm_and_ccm_are_authenticated_by_sp800_38c_and_sp800_38d() {
    for mode in MODES {
        assert_eq!(mode.authenticated(), matches!(mode, AESMode::GCM | AESMode::CCM | AESMode::CCM8), "{}", mode.as_str());
    }
}

#[test]
fn ciphertext_stealing_is_unpadded_by_rfc3962_and_sp800_38a_addendum() {
    assert_eq!(AESMode::CBC_CS3.as_str(), "CBC-CS3");
    assert!(!AESMode::CBC_CS3.padded());
    assert!(AESMode::ECB.padded() && AESMode::CBC.padded());
    for mode in [AESMode::CFB, AESMode::OFB, AESMode::CTR, AESMode::GCM, AESMode::CCM, AESMode::CCM8] {
        assert!(!mode.padded(), "{}", mode.as_str());
    }
}
