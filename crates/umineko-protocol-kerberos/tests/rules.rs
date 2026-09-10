use umineko_protocol_kerberos::helpers::{KerberosCredentialCache, KerberosCredentials, KerberosKey, KerberosKeytab, KerberosKeytabEntry};
use umineko_protocol_kerberos::protocol::{KerberosEncryptedData, KerberosTicket};
use umineko_protocol_kerberos::{KerberosChecksumType, KerberosEncryptionType, KerberosError, KerberosKeyUsage, KerberosNameType, KerberosPrincipal, KerberosPrincipalName, KerberosTransport, KerberosVersion};

#[test]
fn simplified_profile_parameters_follow_rfc3961_rfc3962_rfc8009_and_rfc6803() {
    let expected = [
        (KerberosEncryptionType::DES_CBC_CRC, 8, 8, 8, 8, 4, KerberosChecksumType::RSA_MD5_DES),
        (KerberosEncryptionType::DES_CBC_MD4, 8, 8, 8, 8, 16, KerberosChecksumType::RSA_MD4_DES),
        (KerberosEncryptionType::DES_CBC_MD5, 8, 8, 8, 8, 16, KerberosChecksumType::RSA_MD5_DES),
        (KerberosEncryptionType::DES3_CBC_SHA1_KD, 24, 21, 8, 8, 20, KerberosChecksumType::HMAC_SHA1_DES3_KD),
        (KerberosEncryptionType::AES128_CTS_HMAC_SHA1_96, 16, 16, 16, 16, 12, KerberosChecksumType::HMAC_SHA1_96_AES128),
        (KerberosEncryptionType::AES256_CTS_HMAC_SHA1_96, 32, 32, 16, 16, 12, KerberosChecksumType::HMAC_SHA1_96_AES256),
        (KerberosEncryptionType::AES128_CTS_HMAC_SHA256_128, 16, 16, 16, 16, 16, KerberosChecksumType::HMAC_SHA256_128_AES128),
        (KerberosEncryptionType::AES256_CTS_HMAC_SHA384_192, 32, 32, 16, 16, 24, KerberosChecksumType::HMAC_SHA384_192_AES256),
        (KerberosEncryptionType::CAMELLIA128_CTS_CMAC, 16, 16, 16, 16, 16, KerberosChecksumType::CMAC_CAMELLIA128),
        (KerberosEncryptionType::CAMELLIA256_CTS_CMAC, 32, 32, 16, 16, 16, KerberosChecksumType::CMAC_CAMELLIA256),
    ];
    for (encryption, key_size, seed_size, block_size, confounder_size, integrity_size, checksum) in expected {
        assert_eq!(encryption.key_size(), Some(key_size), "{encryption}");
        assert_eq!(encryption.seed_size(), Some(seed_size), "{encryption}");
        assert_eq!(encryption.block_size(), Some(block_size), "{encryption}");
        assert_eq!(encryption.confounder_size(), Some(confounder_size), "{encryption}");
        assert_eq!(encryption.integrity_size(), Some(integrity_size), "{encryption}");
        assert_eq!(encryption.checksum(), Some(checksum), "{encryption}");
        assert!(checksum.keyed(), "{checksum}");
    }
}

#[test]
fn message_block_sizes_follow_rfc3961_and_rfc3962() {
    for encryption in [KerberosEncryptionType::DES_CBC_CRC, KerberosEncryptionType::DES_CBC_MD4, KerberosEncryptionType::DES_CBC_MD5, KerberosEncryptionType::DES3_CBC_SHA1_KD] {
        assert_eq!(encryption.message_block_size(), Some(8), "{encryption}");
    }
    for encryption in [KerberosEncryptionType::AES128_CTS_HMAC_SHA1_96, KerberosEncryptionType::AES256_CTS_HMAC_SHA1_96] {
        assert_eq!(encryption.message_block_size(), Some(1), "{encryption}");
    }
}

#[test]
fn default_string_to_key_parameters_follow_rfc3961_rfc3962_rfc8009_and_rfc6803() {
    let expected: [(KerberosEncryptionType, &[u8]); 10] = [
        (KerberosEncryptionType::DES_CBC_CRC, &[]),
        (KerberosEncryptionType::DES_CBC_MD4, &[]),
        (KerberosEncryptionType::DES_CBC_MD5, &[]),
        (KerberosEncryptionType::DES3_CBC_SHA1_KD, &[]),
        (KerberosEncryptionType::AES128_CTS_HMAC_SHA1_96, &[0x00, 0x00, 0x10, 0x00]),
        (KerberosEncryptionType::AES256_CTS_HMAC_SHA1_96, &[0x00, 0x00, 0x10, 0x00]),
        (KerberosEncryptionType::AES128_CTS_HMAC_SHA256_128, &32768u32.to_be_bytes()),
        (KerberosEncryptionType::AES256_CTS_HMAC_SHA384_192, &32768u32.to_be_bytes()),
        (KerberosEncryptionType::CAMELLIA128_CTS_CMAC, &[0x00, 0x00, 0x80, 0x00]),
        (KerberosEncryptionType::CAMELLIA256_CTS_CMAC, &[0x00, 0x00, 0x80, 0x00]),
    ];
    for (encryption, parameters) in expected {
        assert_eq!(encryption.parameters(), Some(parameters), "{encryption}");
    }
}

#[test]
fn rc4_encryption_types_follow_rfc4757() {
    for encryption in [KerberosEncryptionType::RC4_HMAC, KerberosEncryptionType::RC4_HMAC_EXP] {
        assert_eq!(encryption.key_size(), Some(16), "{encryption}");
        assert_eq!(encryption.block_size(), None, "{encryption}");
        assert_eq!(encryption.confounder_size(), Some(8), "{encryption}");
        assert_eq!(encryption.integrity_size(), Some(16), "{encryption}");
        assert_eq!(encryption.checksum(), Some(KerberosChecksumType::HMAC_MD5), "{encryption}");
    }
}

#[test]
fn deprecations_follow_rfc6649_and_rfc8429() {
    let encryptions = [1, 2, 3, 5, 7, 16, 23, 24];
    for encryption in KerberosEncryptionType::ALL {
        assert_eq!(encryption.deprecated(), encryptions.contains(&encryption.number()), "{encryption}");
    }
    let checksums = [1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, -138];
    for checksum in KerberosChecksumType::ALL {
        assert_eq!(checksum.deprecated(), checksums.contains(&checksum.number()), "{checksum} {}", checksum.number());
    }
}

#[test]
fn confounded_checksums_follow_rfc3961() {
    for checksum in KerberosChecksumType::ALL {
        let expected = matches!(checksum, KerberosChecksumType::RSA_MD4_DES | KerberosChecksumType::DES_MAC | KerberosChecksumType::RSA_MD5_DES);
        if checksum != KerberosChecksumType::RSA_MD5_DES3 {
            assert_eq!(checksum.confounded(), expected, "{checksum}");
        }
        if checksum.confounded() {
            assert!(checksum.keyed(), "{checksum}");
        }
    }
    for checksum in [KerberosChecksumType::CRC32, KerberosChecksumType::RSA_MD4, KerberosChecksumType::RSA_MD5, KerberosChecksumType::NIST_SHA, KerberosChecksumType::SHA1] {
        assert!(!checksum.keyed(), "{checksum}");
    }
}

#[test]
fn key_usage_numbers_follow_rfc4120() {
    let expected = [
        (KerberosKeyUsage::AS_REQ_TIMESTAMP, 1), (KerberosKeyUsage::TICKET, 2), (KerberosKeyUsage::AS_REP_PART, 3), (KerberosKeyUsage::TGS_REQ_AUTHORIZATION_SESSION, 4),
        (KerberosKeyUsage::TGS_REQ_AUTHORIZATION_SUBKEY, 5), (KerberosKeyUsage::TGS_REQ_AUTHENTICATOR_CHECKSUM, 6), (KerberosKeyUsage::TGS_REQ_AUTHENTICATOR, 7),
        (KerberosKeyUsage::TGS_REP_PART_SESSION, 8), (KerberosKeyUsage::TGS_REP_PART_SUBKEY, 9), (KerberosKeyUsage::AP_REQ_AUTHENTICATOR_CHECKSUM, 10),
        (KerberosKeyUsage::AP_REQ_AUTHENTICATOR, 11), (KerberosKeyUsage::AP_REP_PART, 12), (KerberosKeyUsage::PRIV_PART, 13), (KerberosKeyUsage::CRED_PART, 14),
        (KerberosKeyUsage::SAFE_CHECKSUM, 15), (KerberosKeyUsage::AD_KDC_ISSUED_CHECKSUM, 19), (KerberosKeyUsage::APPLICATION_ENCRYPTION, 1024), (KerberosKeyUsage::APPLICATION_CHECKSUM, 1025),
    ];
    for (usage, number) in expected {
        assert_eq!(usage.0, number);
    }
}

#[test]
fn kdc_transport_uses_port_88_and_tcp_length_framing_by_rfc4120() {
    assert_eq!(KerberosTransport::PORT, 88);
    assert!(KerberosTransport::TCP.framed());
    assert!(!KerberosTransport::UDP.framed());
}

#[test]
fn tls_server_principals_follow_rfc2712() {
    let principal = KerberosPrincipal::host("server.example.com", "EXAMPLE.COM");
    assert_eq!(principal.name.components, ["host", "server.example.com"]);
    assert_eq!(principal.realm, "EXAMPLE.COM");
}

fn principal(kind: KerberosNameType, components: &[&str], realm: &str) -> KerberosPrincipal {
    KerberosPrincipal::new(KerberosPrincipalName::new(kind, components.iter().map(|component| component.to_string()).collect()), realm)
}

#[test]
fn principal_names_differing_only_in_name_type_are_equivalent_by_rfc4120() {
    let host = principal(KerberosNameType::ServiceHost, &["host", "server.example.com"], "EXAMPLE.COM");
    for kind in KerberosNameType::ALL {
        assert!(host.matches(&principal(kind, &["host", "server.example.com"], "EXAMPLE.COM")), "{kind}");
    }
    assert!(!host.matches(&principal(KerberosNameType::ServiceHost, &["host", "other.example.com"], "EXAMPLE.COM")));
    assert!(!host.matches(&principal(KerberosNameType::ServiceHost, &["host", "server.example.com"], "OTHER.COM")));
    assert!(!host.matches(&principal(KerberosNameType::ServiceHost, &["host"], "EXAMPLE.COM")));
}

#[test]
fn keytab_lookups_ignore_the_name_type_by_rfc4120() {
    let stored = principal(KerberosNameType::Principal, &["host", "server.example.com"], "EXAMPLE.COM");
    let requested = KerberosPrincipal::host("server.example.com", "EXAMPLE.COM");
    let key = |encryption: KerberosEncryptionType, byte: u8| KerberosKey::new(encryption, &vec![byte; encryption.key_size().unwrap()]).unwrap();
    let mut keytab = KerberosKeytab::new();
    keytab.insert(KerberosKeytabEntry { principal: stored.clone(), timestamp: 0, version: 1, key: key(KerberosEncryptionType::AES256_CTS_HMAC_SHA1_96, 1) });
    keytab.insert(KerberosKeytabEntry { principal: stored.clone(), timestamp: 0, version: 2, key: key(KerberosEncryptionType::AES256_CTS_HMAC_SHA1_96, 2) });
    keytab.insert(KerberosKeytabEntry { principal: stored.clone(), timestamp: 0, version: 2, key: key(KerberosEncryptionType::AES128_CTS_HMAC_SHA256_128, 3) });
    assert_eq!(keytab.find(&requested, Some(1), KerberosEncryptionType::AES256_CTS_HMAC_SHA1_96).map(|entry| entry.key.as_slice()[0]), Some(1));
    assert_eq!(keytab.find(&requested, Some(2), KerberosEncryptionType::AES128_CTS_HMAC_SHA256_128).map(|entry| entry.key.as_slice()[0]), Some(3));
    assert_eq!(keytab.find(&requested, Some(3), KerberosEncryptionType::AES256_CTS_HMAC_SHA1_96), None);
    assert_eq!(keytab.find(&requested, None, KerberosEncryptionType::CAMELLIA256_CTS_CMAC), None);
    assert_eq!(keytab.find(&principal(KerberosNameType::Principal, &["host", "server.example.com"], "OTHER.COM"), None, KerberosEncryptionType::AES256_CTS_HMAC_SHA1_96), None);
    assert_eq!(keytab.remove(&requested), 3);
    assert!(keytab.entries().is_empty());
}

#[test]
fn credential_caches_ignore_the_name_type_and_expire_at_the_end_time_by_rfc4120() {
    let client = principal(KerberosNameType::Principal, &["user"], "EXAMPLE.COM");
    let server = KerberosPrincipal::host("server.example.com", "EXAMPLE.COM");
    let key = KerberosKey::new(KerberosEncryptionType::AES256_CTS_HMAC_SHA1_96, &[7; 32]).unwrap();
    let ticket = KerberosTicket { version: KerberosVersion::V5, realm: "EXAMPLE.COM".to_string(), server: server.name.clone(), encrypted: KerberosEncryptedData { encryption: KerberosEncryptionType::AES256_CTS_HMAC_SHA1_96, version: Some(2), cipher: vec![1, 2, 3] } };
    let credentials = KerberosCredentials { client: client.clone(), server: server.clone(), key, ticket, flags: 0, authentication_time: 100, start_time: None, end_time: 200, renew_until: None };
    let mut cache = KerberosCredentialCache::new();
    cache.insert(credentials.clone());
    cache.insert(credentials.clone());
    assert_eq!(cache.credentials().len(), 1);
    assert!(cache.find(&principal(KerberosNameType::Unknown, &["user"], "EXAMPLE.COM"), &principal(KerberosNameType::Principal, &["host", "server.example.com"], "EXAMPLE.COM")).is_some());
    assert!(!credentials.expired(199));
    assert!(credentials.expired(200));
    assert_eq!(cache.remove_expired(199), 0);
    assert_eq!(cache.remove_expired(200), 1);
    assert!(cache.credentials().is_empty());
}

#[test]
fn encrypted_data_is_only_decrypted_with_a_key_of_its_encryption_type() {
    let data = KerberosEncryptedData { encryption: KerberosEncryptionType::AES128_CTS_HMAC_SHA1_96, version: None, cipher: vec![0; 32] };
    let key = KerberosKey::new(KerberosEncryptionType::AES256_CTS_HMAC_SHA1_96, &[0; 32]).unwrap();
    assert_eq!(data.decrypt(&key, KerberosKeyUsage::TICKET), Err(KerberosError::EncryptionType));
}

#[test]
fn keys_must_match_the_encryption_type_key_size() {
    assert!(KerberosKey::new(KerberosEncryptionType::AES256_CTS_HMAC_SHA1_96, &[0; 32]).is_ok());
    assert_eq!(KerberosKey::new(KerberosEncryptionType::AES256_CTS_HMAC_SHA1_96, &[0; 16]), Err(KerberosError::Key));
    assert_eq!(KerberosKey::new(KerberosEncryptionType::RSA_ENCRYPTION_ENV_OID, &[0; 16]), Err(KerberosError::EncryptionType));
}
