use umineko_protocol_tls::{TLSCipher, TLSEncryption, TLSGroup, TLSGroupKind, TLSHash, TLSKeyExchange, TLSMAC, TLSRole, TLSVersion};

const VERSIONS: [TLSVersion; 4] = [TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2, TLSVersion::V1_3];

#[test]
fn cipher_code_points_and_names_are_unique_and_round_trip() {
    for (index, cipher) in TLSCipher::ALL.into_iter().enumerate() {
        assert_eq!(TLSCipher::from_number(cipher.number()), Some(cipher));
        assert_eq!(TLSCipher::from_name(cipher.as_str()), Some(cipher));
        assert!(TLSCipher::ALL[index + 1..].iter().all(|other| other.number() != cipher.number()), "{cipher}");
    }
    for number in [0x001C, 0x001D, 0x0047, 0x0060, 0x0A0A, 0x1A1A, 0xFAFA, 0xFEFE, 0xFF00] {
        assert_eq!(TLSCipher::from_number(number), None, "0x{number:04X}");
    }
}

#[test]
fn tls13_cipher_suites_follow_rfc8446() {
    let expected = [
        (TLSCipher::TLS_AES_128_GCM_SHA256, 0x1301, TLSEncryption::AES_128_GCM, TLSHash::SHA256, 16, 16),
        (TLSCipher::TLS_AES_256_GCM_SHA384, 0x1302, TLSEncryption::AES_256_GCM, TLSHash::SHA384, 32, 16),
        (TLSCipher::TLS_CHACHA20_POLY1305_SHA256, 0x1303, TLSEncryption::CHACHA20_POLY1305, TLSHash::SHA256, 32, 16),
        (TLSCipher::TLS_AES_128_CCM_SHA256, 0x1304, TLSEncryption::AES_128_CCM, TLSHash::SHA256, 16, 16),
        (TLSCipher::TLS_AES_128_CCM_8_SHA256, 0x1305, TLSEncryption::AES_128_CCM_8, TLSHash::SHA256, 16, 8),
    ];
    for (cipher, number, encryption, hash, key_size, tag_size) in expected {
        assert_eq!(cipher.number(), number);
        assert_eq!(cipher.versions(), &[TLSVersion::V1_3]);
        assert_eq!(cipher.key_exchange(), None);
        assert_eq!(cipher.encryption(), encryption);
        assert_eq!(cipher.mac(), None);
        assert_eq!(cipher.hash(TLSVersion::V1_3), Some(hash));
        assert_eq!(cipher.hash(TLSVersion::V1_2), None);
        assert_eq!(cipher.key_size(), key_size);
        assert_eq!(cipher.nonce_size(), 12);
        assert_eq!(cipher.tag_size(), tag_size);
        assert!(cipher.datagram());
    }
}

#[test]
fn tls13_only_cipher_suites_do_not_negotiate_a_key_exchange() {
    for cipher in TLSCipher::ALL {
        if cipher.versions() != [TLSVersion::V1_3] {
            continue;
        }
        assert_eq!(cipher.key_exchange(), None, "{cipher}");
        let encryption = cipher.encryption();
        if encryption.aead() {
            assert_eq!(cipher.mac(), None, "{cipher}");
            assert!(encryption.nonce_size() >= 8, "{cipher}");
        } else {
            assert_eq!(encryption, TLSEncryption::NULL, "{cipher}");
            assert!(cipher.mac().is_some(), "{cipher}");
        }
    }
}

#[test]
fn integrity_only_cipher_suites_follow_rfc9150() {
    assert_eq!(TLSCipher::TLS_SHA256_SHA256.number(), 0xC0B4);
    assert_eq!(TLSCipher::TLS_SHA256_SHA256.encryption(), TLSEncryption::NULL);
    assert_eq!(TLSCipher::TLS_SHA256_SHA256.mac(), Some(TLSMAC::HMAC_SHA256));
    assert_eq!(TLSCipher::TLS_SHA256_SHA256.hash(TLSVersion::V1_3), Some(TLSHash::SHA256));
    assert_eq!(TLSCipher::TLS_SHA384_SHA384.number(), 0xC0B5);
    assert_eq!(TLSCipher::TLS_SHA384_SHA384.encryption(), TLSEncryption::NULL);
    assert_eq!(TLSCipher::TLS_SHA384_SHA384.mac(), Some(TLSMAC::HMAC_SHA384));
    assert_eq!(TLSCipher::TLS_SHA384_SHA384.hash(TLSVersion::V1_3), Some(TLSHash::SHA384));
}

#[test]
fn export_cipher_suites_are_limited_to_tls10_by_rfc4346() {
    for cipher in TLSCipher::ALL {
        let export = cipher.as_str().contains("_EXPORT_");
        assert_eq!(cipher.export(), export, "{cipher}");
        if export {
            assert_eq!(cipher.versions(), &[TLSVersion::V1_0], "{cipher}");
            assert!(matches!(cipher.encryption(), TLSEncryption::RC4_40 | TLSEncryption::RC2_CBC_40 | TLSEncryption::DES40_CBC), "{cipher}");
        }
    }
}

#[test]
fn des_and_idea_cipher_suites_are_removed_from_tls12_by_rfc5246() {
    for cipher in TLSCipher::ALL {
        if matches!(cipher.encryption(), TLSEncryption::DES_CBC | TLSEncryption::DES40_CBC | TLSEncryption::IDEA_CBC) {
            assert!(!cipher.versions().contains(&TLSVersion::V1_2), "{cipher}");
            assert!(!cipher.versions().contains(&TLSVersion::V1_3), "{cipher}");
        }
    }
}

#[test]
fn rc4_cipher_suites_are_not_usable_with_dtls_by_rfc6347() {
    for cipher in TLSCipher::ALL {
        if matches!(cipher.encryption(), TLSEncryption::RC4_40 | TLSEncryption::RC4_128) {
            assert!(!cipher.datagram(), "{cipher}");
        }
    }
}

#[test]
fn aead_cipher_suites_with_a_key_exchange_require_tls12() {
    for cipher in TLSCipher::ALL {
        if cipher.encryption().aead() && cipher.key_exchange().is_some() {
            assert_eq!(cipher.mac(), None, "{cipher}");
            assert!(cipher.versions().contains(&TLSVersion::V1_2), "{cipher}");
            assert!(!cipher.versions().contains(&TLSVersion::V1_0), "{cipher}");
            assert!(!cipher.versions().contains(&TLSVersion::V1_1), "{cipher}");
        }
    }
}

#[test]
fn cipher_suites_with_sha256_or_sha384_record_macs_require_tls12() {
    for cipher in TLSCipher::ALL {
        if matches!(cipher.mac(), Some(TLSMAC::HMAC_SHA256 | TLSMAC::HMAC_SHA384)) {
            assert!(!cipher.versions().contains(&TLSVersion::V1_0), "{cipher}");
            assert!(!cipher.versions().contains(&TLSVersion::V1_1), "{cipher}");
        }
    }
}

#[test]
fn cbc_encryptions_use_a_block_sized_initialization_vector() {
    for encryption in TLSEncryption::ALL {
        assert_eq!(TLSEncryption::from_name(encryption.as_str()), Some(encryption));
        if encryption.as_str().contains("_CBC") {
            assert!(!encryption.aead(), "{encryption}");
            assert_eq!(Some(encryption.nonce_size()), encryption.block_size(), "{encryption}");
            assert_eq!(encryption.tag_size(), 0, "{encryption}");
        }
        if encryption.aead() {
            assert!(encryption.tag_size() >= 8, "{encryption}");
        }
    }
}

#[test]
fn bulk_encryption_key_sizes_follow_their_algorithms() {
    let expected = [
        (TLSEncryption::NULL, 0),
        (TLSEncryption::RC4_40, 5),
        (TLSEncryption::RC4_128, 16),
        (TLSEncryption::RC2_CBC_40, 5),
        (TLSEncryption::DES40_CBC, 5),
        (TLSEncryption::DES_CBC, 8),
        (TLSEncryption::IDEA_CBC, 16),
        (TLSEncryption::TRIPLEDES_EDE_CBC, 24),
        (TLSEncryption::AES_128_CBC, 16),
        (TLSEncryption::AES_256_CBC, 32),
        (TLSEncryption::CAMELLIA_128_GCM, 16),
        (TLSEncryption::CAMELLIA_256_GCM, 32),
        (TLSEncryption::ARIA_128_CBC, 16),
        (TLSEncryption::ARIA_256_GCM, 32),
        (TLSEncryption::SEED_CBC, 16),
        (TLSEncryption::SM4_GCM, 16),
        (TLSEncryption::AEGIS_128L, 16),
        (TLSEncryption::AEGIS_256, 32),
        (TLSEncryption::ASCONAEAD128, 16),
        (TLSEncryption::KUZNYECHIK_CTR_ACPKM, 32),
        (TLSEncryption::MAGMA_CTR_ACPKM, 32),
        (TLSEncryption::GOST28147_CNT, 32),
    ];
    for (encryption, key_size) in expected {
        assert_eq!(encryption.key_size(), key_size, "{encryption}");
    }
}

#[test]
fn the_prf_hash_follows_the_negotiated_version() {
    for cipher in TLSCipher::ALL {
        let name = cipher.as_str();
        for version in VERSIONS {
            let hash = cipher.hash(version);
            if !cipher.versions().contains(&version) || cipher.signaling() || cipher == TLSCipher::TLS_NULL_WITH_NULL_NULL {
                assert_eq!(hash, None, "{cipher} {version}");
            } else if matches!(version, TLSVersion::V1_0 | TLSVersion::V1_1) {
                assert_eq!(hash, Some(TLSHash::MD5_SHA1), "{cipher} {version}");
            } else if name.starts_with("TLS_GOSTR341112_256_") {
                assert_eq!(hash, Some(TLSHash::STREEBOG256), "{cipher} {version}");
            } else if name.ends_with("_SHA384") {
                assert_eq!(hash, Some(TLSHash::SHA384), "{cipher} {version}");
            } else if name.ends_with("_SHA512") {
                assert_eq!(hash, Some(TLSHash::SHA512), "{cipher} {version}");
            } else if name.ends_with("_SM3") {
                assert_eq!(hash, Some(TLSHash::SM3), "{cipher} {version}");
            } else if name.ends_with("_ASCONHASH256") {
                assert_eq!(hash, Some(TLSHash::ASCONHASH256), "{cipher} {version}");
            } else {
                assert_eq!(hash, Some(TLSHash::SHA256), "{cipher} {version}");
            }
        }
    }
}

#[test]
fn the_record_mac_follows_the_cipher_suite_name() {
    for cipher in TLSCipher::ALL {
        let name = cipher.as_str();
        if cipher.signaling() || cipher == TLSCipher::TLS_NULL_WITH_NULL_NULL || cipher.encryption().aead() {
            assert_eq!(cipher.mac(), None, "{cipher}");
            continue;
        }
        let expected = if name.ends_with("_MD5") {
            TLSMAC::HMAC_MD5
        } else if name.ends_with("_SHA") {
            TLSMAC::HMAC_SHA1
        } else if name.ends_with("_SHA256") {
            TLSMAC::HMAC_SHA256
        } else if name.ends_with("_SHA384") {
            TLSMAC::HMAC_SHA384
        } else if name.ends_with("_KUZNYECHIK_CTR_OMAC") {
            TLSMAC::OMAC_KUZNYECHIK
        } else if name.ends_with("_MAGMA_CTR_OMAC") {
            TLSMAC::OMAC_MAGMA
        } else if name.ends_with("_IMIT") {
            TLSMAC::IMIT_GOST28147
        } else {
            panic!("{cipher} has no record MAC in its name");
        };
        assert_eq!(cipher.mac(), Some(expected), "{cipher}");
    }
    let sizes = [(TLSMAC::HMAC_MD5, 16), (TLSMAC::HMAC_SHA1, 20), (TLSMAC::HMAC_SHA256, 32), (TLSMAC::HMAC_SHA384, 48), (TLSMAC::OMAC_KUZNYECHIK, 16), (TLSMAC::OMAC_MAGMA, 8), (TLSMAC::IMIT_GOST28147, 4)];
    for (mac, size) in sizes {
        assert_eq!(mac.size(), size, "{mac}");
        assert_eq!(TLSMAC::from_name(mac.as_str()), Some(mac));
    }
}

#[test]
fn only_the_scsvs_are_signaling_values() {
    let signaling: Vec<u16> = TLSCipher::ALL.into_iter().filter(|cipher| cipher.signaling()).map(|cipher| cipher.number()).collect();
    assert_eq!(signaling, [0x00FF, 0x5600]);
    assert!(TLSCipher::TLS_FALLBACK_SCSV.versions().contains(&TLSVersion::V1_3));
    assert!(!TLSCipher::TLS_EMPTY_RENEGOTIATION_INFO_SCSV.versions().contains(&TLSVersion::V1_3));
}

#[test]
fn chacha20_poly1305_cipher_suites_follow_rfc7905() {
    for cipher in TLSCipher::ALL.into_iter().filter(|cipher| cipher.encryption() == TLSEncryption::CHACHA20_POLY1305) {
        assert_eq!(cipher.key_size(), 32, "{cipher}");
        assert_eq!(cipher.nonce_size(), 12, "{cipher}");
        assert_eq!(cipher.tag_size(), 16, "{cipher}");
        assert!(cipher.number() >> 8 == 0xCC || cipher.number() == 0x1303, "{cipher}");
    }
}

#[test]
fn gost_cipher_suites_follow_rfc9189_and_rfc9367() {
    let expected = [
        (TLSCipher::TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC, 0xC100, TLSVersion::V1_2, 32, 8, 0, Some(TLSMAC::OMAC_KUZNYECHIK)),
        (TLSCipher::TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC, 0xC101, TLSVersion::V1_2, 32, 4, 0, Some(TLSMAC::OMAC_MAGMA)),
        (TLSCipher::TLS_GOSTR341112_256_WITH_28147_CNT_IMIT, 0xC102, TLSVersion::V1_2, 32, 8, 0, Some(TLSMAC::IMIT_GOST28147)),
        (TLSCipher::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L, 0xC103, TLSVersion::V1_3, 32, 16, 16, None),
        (TLSCipher::TLS_GOSTR341112_256_WITH_MAGMA_MGM_L, 0xC104, TLSVersion::V1_3, 32, 8, 8, None),
        (TLSCipher::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S, 0xC105, TLSVersion::V1_3, 32, 16, 16, None),
        (TLSCipher::TLS_GOSTR341112_256_WITH_MAGMA_MGM_S, 0xC106, TLSVersion::V1_3, 32, 8, 8, None),
    ];
    for (cipher, number, version, key_size, nonce_size, tag_size, mac) in expected {
        assert_eq!(cipher.number(), number);
        assert_eq!(cipher.versions(), &[version]);
        assert_eq!(cipher.key_exchange(), (version == TLSVersion::V1_2).then_some(TLSKeyExchange::GOSTR341112_256));
        assert_eq!(cipher.key_size(), key_size, "{cipher}");
        assert_eq!(cipher.nonce_size(), nonce_size, "{cipher}");
        assert_eq!(cipher.tag_size(), tag_size, "{cipher}");
        assert_eq!(cipher.mac(), mac, "{cipher}");
        assert!(!cipher.datagram(), "{cipher}");
    }
}

#[test]
fn ctr_acpkm_section_sizes_follow_rfc9189_and_rfc8645() {
    for encryption in TLSEncryption::ALL {
        let expected = match encryption {
            TLSEncryption::KUZNYECHIK_CTR_ACPKM => Some(4 * 1024),
            TLSEncryption::MAGMA_CTR_ACPKM => Some(1024),
            _ => None,
        };
        assert_eq!(encryption.section_size(), expected, "{encryption}");
        if let Some(size) = encryption.section_size() {
            assert_eq!(size % encryption.block_size().unwrap(), 0, "{encryption}");
        }
    }
    assert_eq!(TLSCipher::TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC.encryption(), TLSEncryption::KUZNYECHIK_CTR_ACPKM);
    assert_eq!(TLSCipher::TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC.encryption(), TLSEncryption::MAGMA_CTR_ACPKM);
}

#[test]
fn sm4_cipher_suites_follow_rfc8998() {
    for (cipher, number, encryption) in [(TLSCipher::TLS_SM4_GCM_SM3, 0x00C6, TLSEncryption::SM4_GCM), (TLSCipher::TLS_SM4_CCM_SM3, 0x00C7, TLSEncryption::SM4_CCM)] {
        assert_eq!(cipher.number(), number);
        assert_eq!(cipher.versions(), &[TLSVersion::V1_3]);
        assert_eq!(cipher.encryption(), encryption);
        assert_eq!(cipher.hash(TLSVersion::V1_3), Some(TLSHash::SM3));
        assert_eq!((cipher.key_size(), cipher.nonce_size(), cipher.tag_size()), (16, 12, 16));
    }
}

#[test]
fn aegis_cipher_suites_use_128_bit_tags() {
    assert_eq!((TLSCipher::TLS_AEGIS_128L_SHA256.key_size(), TLSCipher::TLS_AEGIS_128L_SHA256.nonce_size(), TLSCipher::TLS_AEGIS_128L_SHA256.tag_size()), (16, 16, 16));
    assert_eq!((TLSCipher::TLS_AEGIS_256_SHA512.key_size(), TLSCipher::TLS_AEGIS_256_SHA512.nonce_size(), TLSCipher::TLS_AEGIS_256_SHA512.tag_size()), (32, 32, 16));
    assert_eq!(TLSCipher::TLS_AEGIS_256_SHA512.hash(TLSVersion::V1_3), Some(TLSHash::SHA512));
}

#[test]
fn key_exchange_properties_follow_their_names() {
    for key_exchange in TLSKeyExchange::ALL {
        let name = key_exchange.as_str();
        assert_eq!(TLSKeyExchange::from_name(name), Some(key_exchange));
        assert_eq!(key_exchange.anonymous(), name.ends_with("_anon"), "{name}");
        assert_eq!(key_exchange.psk(), name.contains("PSK"), "{name}");
        assert_eq!(key_exchange.forward_secrecy(), name.starts_with("DHE_") || name.starts_with("ECDHE_") || name.ends_with("_anon") || name.starts_with("SRP_") || name == "ECCPWD", "{name}");
    }
}

#[test]
fn the_key_exchange_follows_the_cipher_suite_name() {
    for cipher in TLSCipher::ALL {
        let name = cipher.as_str();
        match cipher.key_exchange() {
            Some(TLSKeyExchange::DHE_PSK) => assert!(name.starts_with("TLS_DHE_PSK_WITH_") || name.starts_with("TLS_PSK_DHE_WITH_"), "{name}"),
            Some(key_exchange) => assert!(name.starts_with(&format!("TLS_{}_WITH_", key_exchange.as_str())) || name.starts_with(&format!("TLS_{}_EXPORT_WITH_", key_exchange.as_str())), "{name}"),
            None => assert!(!name.contains("_WITH_") || name == "TLS_NULL_WITH_NULL_NULL" || name.contains("_MGM_"), "{name}"),
        }
    }
}

#[test]
fn group_code_points_and_names_are_unique_and_round_trip() {
    for (index, group) in TLSGroup::ALL.into_iter().enumerate() {
        assert_eq!(TLSGroup::from_number(group.number()), Some(group));
        assert_eq!(TLSGroup::from_name(group.as_str()), Some(group));
        assert!(TLSGroup::ALL[index + 1..].iter().all(|other| other.number() != group.number()), "{group}");
    }
    for number in [0, 0x0A0A, 0x1A1A, 0xFAFA, 0x01FC, 0xFE00, 0xFF00] {
        assert_eq!(TLSGroup::from_number(number), None, "{number}");
    }
}

#[test]
fn tls13_groups_follow_rfc8446() {
    for group in [TLSGroup::SECP256R1, TLSGroup::SECP384R1, TLSGroup::SECP521R1, TLSGroup::X25519, TLSGroup::X448, TLSGroup::FFDHE2048, TLSGroup::FFDHE3072, TLSGroup::FFDHE4096, TLSGroup::FFDHE6144, TLSGroup::FFDHE8192] {
        assert!(group.versions().contains(&TLSVersion::V1_3), "{group}");
    }
    for group in TLSGroup::ALL {
        let number = group.number();
        if (0x0001..=0x0016).contains(&number) || (0x001A..=0x001C).contains(&number) || (0xFF01..=0xFF02).contains(&number) {
            assert!(!group.versions().contains(&TLSVersion::V1_3), "{group}");
        }
        if matches!(group.kind(), TLSGroupKind::KeyEncapsulation | TLSGroupKind::Hybrid) {
            assert_eq!(group.versions(), &[TLSVersion::V1_3], "{group}");
        }
    }
}

#[test]
fn group_kinds_follow_their_names() {
    for group in TLSGroup::ALL {
        let name = group.as_str();
        let kind = if name.starts_with("ffdhe") {
            TLSGroupKind::FiniteField
        } else if name.starts_with("arbitrary_explicit_") {
            TLSGroupKind::Explicit
        } else if name.contains("MLKEM") && name != "MLKEM512" && name != "MLKEM768" && name != "MLKEM1024" {
            TLSGroupKind::Hybrid
        } else if name.starts_with("MLKEM") {
            TLSGroupKind::KeyEncapsulation
        } else {
            TLSGroupKind::EllipticCurve
        };
        assert_eq!(group.kind(), kind, "{name}");
        assert_eq!(group.post_quantum(), name.contains("MLKEM"), "{name}");
        assert_eq!(group.hybrid(), kind == TLSGroupKind::Hybrid, "{name}");
    }
}

#[test]
fn key_share_sizes_follow_their_specifications() {
    let expected = [
        (TLSGroup::SECP256R1, 65, 65),
        (TLSGroup::SECP384R1, 97, 97),
        (TLSGroup::SECP521R1, 133, 133),
        (TLSGroup::X25519, 32, 32),
        (TLSGroup::X448, 56, 56),
        (TLSGroup::FFDHE2048, 256, 256),
        (TLSGroup::FFDHE3072, 384, 384),
        (TLSGroup::FFDHE4096, 512, 512),
        (TLSGroup::FFDHE6144, 768, 768),
        (TLSGroup::FFDHE8192, 1024, 1024),
        (TLSGroup::BRAINPOOLP256R1TLS13, 65, 65),
        (TLSGroup::BRAINPOOLP384R1TLS13, 97, 97),
        (TLSGroup::BRAINPOOLP512R1TLS13, 129, 129),
        (TLSGroup::GC256A, 64, 64),
        (TLSGroup::GC256B, 64, 64),
        (TLSGroup::GC256C, 64, 64),
        (TLSGroup::GC256D, 64, 64),
        (TLSGroup::GC512A, 128, 128),
        (TLSGroup::GC512B, 128, 128),
        (TLSGroup::GC512C, 128, 128),
        (TLSGroup::CURVESM2, 65, 65),
        (TLSGroup::MLKEM512, 800, 768),
        (TLSGroup::MLKEM768, 1184, 1088),
        (TLSGroup::MLKEM1024, 1568, 1568),
        (TLSGroup::X25519MLKEM768, 1216, 1120),
        (TLSGroup::SECP256R1MLKEM768, 1249, 1153),
        (TLSGroup::SECP384R1MLKEM1024, 1665, 1665),
        (TLSGroup::SECP256R1MLKEM512, 865, 833),
        (TLSGroup::MLKEM512X25519, 832, 800),
        (TLSGroup::CURVESM2MLKEM768, 1249, 1153),
    ];
    for (group, client, server) in expected {
        assert_eq!(group.share_size(TLSRole::Client), Some(client), "{group}");
        assert_eq!(group.share_size(TLSRole::Server), Some(server), "{group}");
    }
    let fields = [
        (TLSGroup::SECT163K1, 163), (TLSGroup::SECT163R1, 163), (TLSGroup::SECT163R2, 163), (TLSGroup::SECT193R1, 193), (TLSGroup::SECT193R2, 193),
        (TLSGroup::SECT233K1, 233), (TLSGroup::SECT233R1, 233), (TLSGroup::SECT239K1, 239), (TLSGroup::SECT283K1, 283), (TLSGroup::SECT283R1, 283),
        (TLSGroup::SECT409K1, 409), (TLSGroup::SECT409R1, 409), (TLSGroup::SECT571K1, 571), (TLSGroup::SECT571R1, 571),
        (TLSGroup::SECP160K1, 160), (TLSGroup::SECP160R1, 160), (TLSGroup::SECP160R2, 160), (TLSGroup::SECP192K1, 192), (TLSGroup::SECP192R1, 192),
        (TLSGroup::SECP224K1, 224), (TLSGroup::SECP224R1, 224), (TLSGroup::SECP256K1, 256),
        (TLSGroup::BRAINPOOLP256R1, 256), (TLSGroup::BRAINPOOLP384R1, 384), (TLSGroup::BRAINPOOLP512R1, 512),
    ];
    for (group, bits) in fields {
        let size = 1 + 2 * (bits as usize).div_ceil(8);
        assert_eq!(group.share_size(TLSRole::Client), Some(size), "{group}");
        assert_eq!(group.share_size(TLSRole::Server), Some(size), "{group}");
    }
    for group in [TLSGroup::ARBITRARY_EXPLICIT_PRIME_CURVES, TLSGroup::ARBITRARY_EXPLICIT_CHAR2_CURVES] {
        assert_eq!(group.share_size(TLSRole::Client), None, "{group}");
        assert_eq!(group.share_size(TLSRole::Server), None, "{group}");
    }
}
