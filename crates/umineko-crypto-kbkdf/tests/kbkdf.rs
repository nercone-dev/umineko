use umineko_crypto_cmac::CMACCipher;
use umineko_crypto_hmac::HMACHash;
use umineko_crypto_kbkdf::{KBKDF, KBKDFError, KBKDFMode, PRF};

#[test]
fn mode_names_round_trip() {
    assert_eq!(KBKDFMode::ALL.len(), 3);
    for mode in KBKDFMode::ALL {
        assert_eq!(KBKDFMode::from_name(mode.as_str()), Some(mode));
    }
}

#[test]
fn counters_are_at_most_32_bits_by_sp800_108r1() {
    for mode in KBKDFMode::ALL {
        for size in [0, 5, 8] {
            assert_eq!(KBKDF::new(HMACHash::SHA2_256, mode, Some(size), 4), Err(KBKDFError::Counter), "{mode} {size}");
        }
        for size in 1..=4 {
            let kdf = KBKDF::new(HMACHash::SHA2_256, mode, Some(size), 4).unwrap();
            assert_eq!(kdf.counter_size(), Some(size));
            assert_eq!(kdf.maximum_blocks(), (1u64 << (8 * size)) - 1, "{mode} {size}");
        }
    }
}

#[test]
fn the_counter_is_optional_only_in_feedback_and_double_pipeline_modes_by_sp800_108r1() {
    assert_eq!(KBKDF::new(HMACHash::SHA2_256, KBKDFMode::Counter, None, 4), Err(KBKDFError::Counter));
    for mode in [KBKDFMode::Feedback, KBKDFMode::DoublePipeline] {
        let kdf = KBKDF::new(HMACHash::SHA2_256, mode, None, 4).unwrap();
        assert_eq!(kdf.maximum_blocks(), (1u64 << 32) - 1, "{mode}");
        assert_eq!(kdf.input(1, b"chain", b"fixed"), Ok(b"chainfixed".to_vec()), "{mode}");
    }
}

#[test]
fn the_iteration_counter_starts_at_one_and_fits_in_r_bits_by_sp800_108r1() {
    let kdf = KBKDF::new(HMACHash::SHA2_256, KBKDFMode::Counter, Some(1), 4).unwrap();
    assert_eq!(kdf.input(0, &[], b"fixed"), Err(KBKDFError::Counter));
    assert_eq!(kdf.input(1, &[], b"fixed"), Ok([&[0x01][..], b"fixed"].concat()));
    assert_eq!(kdf.input(255, &[], b"fixed"), Ok([&[0xFF][..], b"fixed"].concat()));
    assert_eq!(kdf.input(256, &[], b"fixed"), Err(KBKDFError::Counter));
    let kdf = KBKDF::new(HMACHash::SHA2_256, KBKDFMode::Feedback, Some(2), 4).unwrap();
    assert_eq!(kdf.input(0x0102, b"previous", b"fixed"), Ok([&b"previous"[..], &[0x01, 0x02], b"fixed"].concat()));
}

#[test]
fn the_fixed_input_is_label_separator_context_and_length_in_bits_by_sp800_108r1() {
    let kdf = KBKDF::new(HMACHash::SHA2_256, KBKDFMode::Counter, Some(4), 2).unwrap();
    assert_eq!(kdf.fixed(b"label", b"context", 32), Ok([&b"label"[..], &[0x00], b"context", &[0x01, 0x00]].concat()));
    assert_eq!(kdf.fixed(b"label", b"context", 0), Err(KBKDFError::Length));
    let kdf = KBKDF::new(HMACHash::SHA2_256, KBKDFMode::Counter, Some(4), 1).unwrap();
    assert_eq!(kdf.fixed(&[], &[], 31), Ok(vec![0x00, 0xF8]));
    assert_eq!(kdf.fixed(&[], &[], 32), Err(KBKDFError::Length));
}

#[test]
fn kdf_hmac_sha2_inputs_follow_rfc8009() {
    let kdf = KBKDF::new(HMACHash::SHA2_256, KBKDFMode::Counter, Some(4), 4).unwrap();
    let constant = [0x00, 0x00, 0x00, 0x02, 0x99];
    let fixed = kdf.fixed(&constant, &[], 16).unwrap();
    assert_eq!(fixed, vec![0x00, 0x00, 0x00, 0x02, 0x99, 0x00, 0x00, 0x00, 0x00, 0x80]);
    assert_eq!(kdf.input(1, &[], &fixed), Ok(vec![0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x99, 0x00, 0x00, 0x00, 0x00, 0x80]));
    for (length, encoded) in [(16, [0x00, 0x00, 0x00, 0x80]), (24, [0x00, 0x00, 0x00, 0xC0]), (32, [0x00, 0x00, 0x01, 0x00]), (48, [0x00, 0x00, 0x01, 0x80])] {
        assert_eq!(kdf.fixed(b"prf", b"octets", length), Ok([&b"prf"[..], &[0x00], b"octets", &encoded].concat()), "{length}");
    }
}

#[test]
fn kdf_feedback_cmac_inputs_follow_rfc6803() {
    let kdf = KBKDF::new(CMACCipher::Camellia128, KBKDFMode::Feedback, Some(4), 4).unwrap();
    let constant = [0x00, 0x00, 0x00, 0x02, 0xAA];
    let fixed = kdf.fixed(&constant, &[], 16).unwrap();
    let previous = [0x11; 16];
    assert_eq!(kdf.input(2, &previous, &fixed), Ok([&previous[..], &[0x00, 0x00, 0x00, 0x02], &constant, &[0x00], &[0x00, 0x00, 0x00, 0x80]].concat()));
    assert_eq!((kdf.prf().output_size(), PRF::key_size(kdf.prf())), (16, Some(16)));
    assert_eq!((CMACCipher::Camellia256.output_size(), PRF::key_size(&CMACCipher::Camellia256)), (16, Some(32)));
    assert_eq!((HMACHash::SHA2_384.output_size(), PRF::key_size(&HMACHash::SHA2_384)), (48, None));
}

#[test]
fn derivation_rejects_invalid_keys_ivs_and_lengths() {
    let kdf = KBKDF::new(CMACCipher::AES128, KBKDFMode::Feedback, Some(4), 4).unwrap();
    assert_eq!(kdf.derive(&[0; 15], b"label", &[], &[0; 16], &mut [0; 16]), Err(KBKDFError::Key));
    assert_eq!(kdf.derive(&[0; 17], b"label", &[], &[0; 16], &mut [0; 16]), Err(KBKDFError::Key));
    for mode in [KBKDFMode::Counter, KBKDFMode::DoublePipeline] {
        let kdf = KBKDF::new(HMACHash::SHA2_256, mode, Some(4), 4).unwrap();
        assert_eq!(kdf.derive(&[0; 32], b"label", &[], &[0; 32], &mut [0; 32]), Err(KBKDFError::IV), "{mode}");
        assert_eq!(kdf.derive(&[0; 32], b"label", &[], &[], &mut []), Err(KBKDFError::Length), "{mode}");
    }
    let kdf = KBKDF::new(HMACHash::SHA2_256, KBKDFMode::Counter, Some(1), 4).unwrap();
    assert_eq!(kdf.derive(&[0; 32], b"label", &[], &[], &mut vec![0; 255 * 32 + 1]), Err(KBKDFError::Length));
}

#[test]
fn provider_requests_name_the_mode_prf_and_encodings() {
    let request = KBKDF::new(HMACHash::SHA2_384, KBKDFMode::Counter, Some(4), 4).unwrap().request().unwrap();
    assert_eq!((request.algorithm, request.prf, request.counter_size, request.length_size), ("KBKDF-Counter", Some("HMAC-SHA-384"), 4, 4));
    let request = KBKDF::new(CMACCipher::Camellia256, KBKDFMode::Feedback, None, 2).unwrap().request().unwrap();
    assert_eq!((request.algorithm, request.prf, request.counter_size, request.length_size), ("KBKDF-Feedback", Some("CMAC-Camellia-256"), 0, 2));
    let request = KBKDF::new(HMACHash::SHA2_256, KBKDFMode::DoublePipeline, Some(1), 8).unwrap().request().unwrap();
    assert_eq!((request.algorithm, request.counter_size, request.length_size), ("KBKDF-Double-Pipeline", 1, 8));
}
