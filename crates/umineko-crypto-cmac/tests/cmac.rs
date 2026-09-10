use umineko_crypto_cmac::{CMAC, CMACCipher, CMACError};

#[test]
fn cipher_parameters_follow_rfc4493_sp800_38b_and_rfc6803() {
    let expected = [(CMACCipher::AES128, 16, "AES-128"), (CMACCipher::AES192, 24, "AES-192"), (CMACCipher::AES256, 32, "AES-256"), (CMACCipher::Camellia128, 16, "Camellia-128"), (CMACCipher::Camellia192, 24, "Camellia-192"), (CMACCipher::Camellia256, 32, "Camellia-256")];
    assert_eq!(CMACCipher::ALL.len(), expected.len());
    for (cipher, key_size, cipher_name) in expected {
        assert_eq!(cipher.key_size(), key_size, "{cipher}");
        assert_eq!(cipher.block_size(), 16, "{cipher}");
        assert_eq!(cipher.tag_size(), 16, "{cipher}");
        assert_eq!(cipher.cipher_name(), cipher_name, "{cipher}");
        assert_eq!(CMACCipher::from_name(cipher.as_str()), Some(cipher));
    }
}

#[test]
fn tags_of_at_least_64_bits_are_accepted_by_sp800_38b() {
    for cipher in CMACCipher::ALL {
        assert_eq!(cipher.minimum_tag_size(), 8, "{cipher}");
        assert!(cipher.minimum_tag_size() <= cipher.tag_size(), "{cipher}");
    }
}

#[test]
fn keys_must_match_the_block_cipher_key_size() {
    for cipher in CMACCipher::ALL {
        for size in [0, cipher.key_size() - 1, cipher.key_size() + 1] {
            assert_eq!(CMAC::new(cipher, &vec![0; size]).err(), Some(CMACError::Key), "{cipher} {size}");
            assert_eq!(CMAC::tag(cipher, &vec![0; size], b"data", &mut [0; 16]), Err(CMACError::Key), "{cipher} {size}");
        }
    }
}

#[test]
fn provider_requests_carry_the_algorithm_and_key() {
    let key = [0x2B; 32];
    let request = CMAC::request(CMACCipher::Camellia256, &key);
    assert_eq!(request.algorithm, "CMAC-Camellia-256");
    assert_eq!(request.key, Some(&key[..]));
}
