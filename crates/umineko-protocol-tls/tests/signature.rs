use umineko_protocol_tls::{TLSHashAlgorithm, TLSSignatureAlgorithm, TLSSignatureScheme};

const SIGNATURE_SCHEMES: &[(u16, &str, &str)] = &[
    (0x0201, "rsa_pkcs1_sha1", "N"),
    (0x0203, "ecdsa_sha1", "N"),
    (0x0401, "rsa_pkcs1_sha256", "Y"),
    (0x0403, "ecdsa_secp256r1_sha256", "Y"),
    (0x0420, "rsa_pkcs1_sha256_legacy", "N"),
    (0x0501, "rsa_pkcs1_sha384", "Y"),
    (0x0503, "ecdsa_secp384r1_sha384", "Y"),
    (0x0520, "rsa_pkcs1_sha384_legacy", "N"),
    (0x0601, "rsa_pkcs1_sha512", "Y"),
    (0x0603, "ecdsa_secp521r1_sha512", "Y"),
    (0x0620, "rsa_pkcs1_sha512_legacy", "N"),
    (0x0704, "eccsi_sha256", "N"),
    (0x0705, "iso_ibs1", "N"),
    (0x0706, "iso_ibs2", "N"),
    (0x0707, "iso_chinese_ibs", "N"),
    (0x0708, "sm2sig_sm3", "N"),
    (0x0709, "gostr34102012_256a", "N"),
    (0x070A, "gostr34102012_256b", "N"),
    (0x070B, "gostr34102012_256c", "N"),
    (0x070C, "gostr34102012_256d", "N"),
    (0x070D, "gostr34102012_512a", "N"),
    (0x070E, "gostr34102012_512b", "N"),
    (0x070F, "gostr34102012_512c", "N"),
    (0x0804, "rsa_pss_rsae_sha256", "Y"),
    (0x0805, "rsa_pss_rsae_sha384", "Y"),
    (0x0806, "rsa_pss_rsae_sha512", "Y"),
    (0x0807, "ed25519", "Y"),
    (0x0808, "ed448", "Y"),
    (0x0809, "rsa_pss_pss_sha256", "Y"),
    (0x080A, "rsa_pss_pss_sha384", "Y"),
    (0x080B, "rsa_pss_pss_sha512", "Y"),
    (0x081A, "ecdsa_brainpoolP256r1tls13_sha256", "N"),
    (0x081B, "ecdsa_brainpoolP384r1tls13_sha384", "N"),
    (0x081C, "ecdsa_brainpoolP512r1tls13_sha512", "N"),
    (0x0904, "mldsa44", "N"),
    (0x0905, "mldsa65", "N"),
    (0x0906, "mldsa87", "N"),
    (0x0911, "slhdsa_sha2_128s", "N"),
    (0x0912, "slhdsa_sha2_128f", "N"),
    (0x0913, "slhdsa_sha2_192s", "N"),
    (0x0914, "slhdsa_sha2_192f", "N"),
    (0x0915, "slhdsa_sha2_256s", "N"),
    (0x0916, "slhdsa_sha2_256f", "N"),
    (0x0917, "slhdsa_shake_128s", "N"),
    (0x0918, "slhdsa_shake_128f", "N"),
    (0x0919, "slhdsa_shake_192s", "N"),
    (0x091A, "slhdsa_shake_192f", "N"),
    (0x091B, "slhdsa_shake_256s", "N"),
    (0x091C, "slhdsa_shake_256f", "N"),
];

const SIGNATURE_ALGORITHMS: &[(u8, &str, bool, &str)] = &[
    (0, "anonymous", true, "N"),
    (1, "rsa", true, "Y"),
    (2, "dsa", true, "N"),
    (3, "ecdsa", true, "Y"),
    (7, "ed25519", true, "Y"),
    (8, "ed448", true, "Y"),
    (64, "gostr34102012_256", true, "N"),
    (65, "gostr34102012_512", true, "N"),
];

const HASH_ALGORITHMS: &[(u8, &str, bool, &str)] = &[
    (0, "none", true, "Y"),
    (1, "md5", true, "D"),
    (2, "sha1", true, "D"),
    (3, "sha224", true, "D"),
    (4, "sha256", true, "Y"),
    (5, "sha384", true, "Y"),
    (6, "sha512", true, "Y"),
    (8, "Intrinsic", true, "Y"),
];

#[test]
fn the_signature_schemes_match_the_iana_registry() {
    assert_eq!(TLSSignatureScheme::ALL.len(), SIGNATURE_SCHEMES.len());
    for &(number, name, recommendation) in SIGNATURE_SCHEMES {
        let scheme = TLSSignatureScheme::from_number(number).unwrap_or_else(|| panic!("0x{number:04X} {name} is missing"));
        assert_eq!(scheme.as_str(), name);
        assert_eq!(TLSSignatureScheme::from_name(name), Some(scheme));
        assert_eq!(scheme.recommendation().as_str(), recommendation, "{name}");
    }
}

#[test]
fn reserved_and_unassigned_signature_schemes_are_not_assigned() {
    for number in [0x0000, 0x0101, 0x0200, 0x0202, 0x0301, 0x0402, 0x041F, 0x0421, 0x0502, 0x0602, 0x0703, 0x0710, 0x07FF, 0x0800, 0x0803, 0x080C, 0x0819, 0x081D, 0x0840, 0x0841, 0x0903, 0x0907, 0x0910, 0x091D, 0x0A00, 0x0A04, 0xFE00, 0xFFFF] {
        assert_eq!(TLSSignatureScheme::from_number(number), None, "0x{number:04X}");
    }
}

#[test]
fn signature_scheme_code_points_and_names_are_unique() {
    for (index, scheme) in TLSSignatureScheme::ALL.into_iter().enumerate() {
        assert!(TLSSignatureScheme::ALL[index + 1..].iter().all(|other| other.number() != scheme.number() && other.as_str() != scheme.as_str()), "{scheme}");
    }
}

#[test]
fn only_ml_dsa_and_slh_dsa_schemes_are_post_quantum() {
    for scheme in TLSSignatureScheme::ALL {
        assert_eq!(scheme.post_quantum(), scheme.as_str().starts_with("mldsa") || scheme.as_str().starts_with("slhdsa"), "{scheme}");
    }
}

#[test]
fn the_signature_algorithms_match_the_iana_registry() {
    assert_eq!(TLSSignatureAlgorithm::ALL.len(), SIGNATURE_ALGORITHMS.len());
    for &(number, name, datagram, recommendation) in SIGNATURE_ALGORITHMS {
        let algorithm = TLSSignatureAlgorithm::from_number(number).unwrap_or_else(|| panic!("{number} {name} is missing"));
        assert_eq!(algorithm.as_str(), name);
        assert_eq!(TLSSignatureAlgorithm::from_name(name), Some(algorithm));
        assert_eq!(algorithm.datagram(), datagram, "{name}");
        assert_eq!(algorithm.recommendation().as_str(), recommendation, "{name}");
    }
    for number in [4, 5, 6, 9, 63, 66, 223, 224, 255] {
        assert_eq!(TLSSignatureAlgorithm::from_number(number), None, "{number}");
    }
}

#[test]
fn the_hash_algorithms_match_the_iana_registry() {
    assert_eq!(TLSHashAlgorithm::ALL.len(), HASH_ALGORITHMS.len());
    for &(number, name, datagram, recommendation) in HASH_ALGORITHMS {
        let algorithm = TLSHashAlgorithm::from_number(number).unwrap_or_else(|| panic!("{number} {name} is missing"));
        assert_eq!(algorithm.as_str(), name);
        assert_eq!(TLSHashAlgorithm::from_name(name), Some(algorithm));
        assert_eq!(algorithm.datagram(), datagram, "{name}");
        assert_eq!(algorithm.recommendation().as_str(), recommendation, "{name}");
    }
    for number in [7, 9, 223, 224, 255] {
        assert_eq!(TLSHashAlgorithm::from_number(number), None, "{number}");
    }
}
