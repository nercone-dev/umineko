use umineko_crypto_random::{DRBG, DRBGCipher, DRBGHash, RandomError, SystemRandom};

#[test]
fn hash_based_parameters_follow_sp800_90a_table2() {
    let expected = [(DRBGHash::SHA1, 160, 440, 128, "SHA-1"), (DRBGHash::SHA2_224, 224, 440, 192, "SHA-224"), (DRBGHash::SHA2_512_224, 224, 440, 192, "SHA-512/224"), (DRBGHash::SHA2_256, 256, 440, 256, "SHA-256"), (DRBGHash::SHA2_512_256, 256, 440, 256, "SHA-512/256"), (DRBGHash::SHA2_384, 384, 888, 256, "SHA-384"), (DRBGHash::SHA2_512, 512, 888, 256, "SHA-512")];
    assert_eq!(DRBGHash::ALL.len(), expected.len());
    for (hash, outlen, seedlen, strength, name) in expected {
        assert_eq!(hash.output_size() * 8, outlen, "{name}");
        assert_eq!(hash.seed_size() * 8, seedlen, "{name}");
        assert_eq!(hash.security_strength(), strength, "{name}");
        assert_eq!(hash.hash_name(), name);
        for drbg in [DRBG::Hash(hash), DRBG::HMAC(hash)] {
            assert_eq!(drbg.security_strength(), strength, "{drbg}");
            assert_eq!(drbg.minimum_entropy_size(strength) * 8, strength, "{drbg}");
            assert_eq!(drbg.maximum_entropy_size() * 8, 1 << 35, "{drbg}");
            assert_eq!(drbg.maximum_input_size() * 8, 1 << 35, "{drbg}");
            assert_eq!(drbg.maximum_request_size() as u64 * 8, 1 << 19, "{drbg}");
            assert_eq!(drbg.reseed_interval(), 1 << 48, "{drbg}");
            assert!(drbg.nonce_required(), "{drbg}");
        }
        assert_eq!(DRBG::Hash(hash).seed_size().map(|size| size * 8), Some(seedlen));
        assert_eq!(DRBG::HMAC(hash).seed_size(), None);
    }
}

#[test]
fn ctr_parameters_follow_sp800_90a_table3() {
    let expected = [(DRBGCipher::TDEA, 64, 168, 232, 112, "TDEA", 1u64 << 13, 1u64 << 32), (DRBGCipher::AES128, 128, 128, 256, 128, "AES-128", 1 << 19, 1 << 48), (DRBGCipher::AES192, 128, 192, 320, 192, "AES-192", 1 << 19, 1 << 48), (DRBGCipher::AES256, 128, 256, 384, 256, "AES-256", 1 << 19, 1 << 48)];
    assert_eq!(DRBGCipher::ALL.len(), expected.len());
    for (cipher, blocklen, keylen, seedlen, strength, name, request, interval) in expected {
        assert_eq!(cipher.block_size() * 8, blocklen, "{name}");
        assert_eq!(cipher.key_size() * 8, keylen, "{name}");
        assert_eq!(cipher.seed_size() * 8, seedlen, "{name}");
        assert_eq!(cipher.security_strength(), strength, "{name}");
        assert_eq!(cipher.cipher_name(), name);
        for derivation in [true, false] {
            let drbg = DRBG::CTR { cipher, derivation };
            assert_eq!(drbg.security_strength(), strength, "{drbg}");
            assert_eq!(drbg.seed_size().map(|size| size * 8), Some(seedlen), "{drbg}");
            assert_eq!(drbg.maximum_request_size() as u64 * 8, request, "{drbg}");
            assert_eq!(drbg.reseed_interval(), interval, "{drbg}");
            assert_eq!(drbg.nonce_required(), derivation, "{drbg}");
            if derivation {
                assert_eq!(drbg.minimum_entropy_size(strength) * 8, strength, "{drbg}");
                assert_eq!(drbg.maximum_entropy_size() * 8, 1 << 35, "{drbg}");
                assert_eq!(drbg.maximum_input_size() * 8, 1 << 35, "{drbg}");
            } else {
                assert_eq!(drbg.minimum_entropy_size(strength) * 8, seedlen, "{drbg}");
                assert_eq!(drbg.maximum_entropy_size() * 8, seedlen as u64, "{drbg}");
                assert_eq!(drbg.maximum_input_size() * 8, seedlen as u64, "{drbg}");
            }
        }
    }
}

#[test]
fn security_strengths_follow_sp800_90a_section8_4() {
    assert_eq!(DRBG::SECURITY_STRENGTHS, [112, 128, 192, 256]);
    for drbg in DRBG::ALL {
        assert!(DRBG::SECURITY_STRENGTHS.contains(&drbg.security_strength()), "{drbg}");
    }
}

#[test]
fn mechanism_names_are_distinct_and_round_trip() {
    for (index, drbg) in DRBG::ALL.into_iter().enumerate() {
        assert_eq!(DRBG::from_name(drbg.as_str()), Some(drbg));
        assert!(DRBG::ALL[index + 1..].iter().all(|other| other.as_str() != drbg.as_str()), "{drbg}");
    }
    assert_eq!(DRBG::ALL.len(), 2 * DRBGHash::ALL.len() + 2 * DRBGCipher::ALL.len());
    assert_eq!(SystemRandom::request().algorithm, SystemRandom::NAME);
}

#[test]
fn instantiation_rejects_invalid_parameters_by_sp800_90a_section9_1() {
    assert_eq!(DRBG::Hash(DRBGHash::SHA1).instantiate(&[0; 32], &[0; 16], &[], 192, false).err(), Some(RandomError::Strength));
    assert_eq!(DRBG::CTR { cipher: DRBGCipher::TDEA, derivation: true }.instantiate(&[0; 32], &[0; 16], &[], 128, false).err(), Some(RandomError::Strength));
    let drbg = DRBG::Hash(DRBGHash::SHA2_256);
    assert_eq!(drbg.instantiate(&[0; 31], &[0; 16], &[], 256, false).err(), Some(RandomError::Entropy));
    assert_eq!(drbg.instantiate(&[0; 32], &[], &[], 256, false).err(), Some(RandomError::Nonce));
    assert_eq!(drbg.instantiate(&[0; 23], &[0; 12], &[], 150, false).err(), Some(RandomError::Entropy));
    let drbg = DRBG::CTR { cipher: DRBGCipher::AES256, derivation: false };
    assert_eq!(drbg.instantiate(&[0; 47], &[], &[], 256, false).err(), Some(RandomError::Entropy));
    assert_eq!(drbg.instantiate(&[0; 49], &[], &[], 256, false).err(), Some(RandomError::Entropy));
    assert_eq!(drbg.instantiate(&[0; 48], &[0; 16], &[], 256, false).err(), Some(RandomError::Nonce));
    assert_eq!(drbg.instantiate(&[0; 48], &[], &[0; 49], 256, false).err(), Some(RandomError::Personalization));
}
