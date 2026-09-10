use umineko_protocol_kerberos::{KerberosChecksumType, KerberosEncryptionType, KerberosErrorCode, KerberosMessageType, KerberosNameType};

const ENCRYPTION_TYPES: &[(i32, &str)] = &[
    (1, "des-cbc-crc"),
    (2, "des-cbc-md4"),
    (3, "des-cbc-md5"),
    (5, "des3-cbc-md5"),
    (7, "des3-cbc-sha1"),
    (9, "dsaWithSHA1-CmsOID"),
    (10, "md5WithRSAEncryption-CmsOID"),
    (11, "sha1WithRSAEncryption-CmsOID"),
    (12, "rc2CBC-EnvOID"),
    (13, "rsaEncryption-EnvOID"),
    (14, "rsaES-OAEP-ENV-OID"),
    (15, "des-ede3-cbc-Env-OID"),
    (16, "des3-cbc-sha1-kd"),
    (17, "aes128-cts-hmac-sha1-96"),
    (18, "aes256-cts-hmac-sha1-96"),
    (19, "aes128-cts-hmac-sha256-128"),
    (20, "aes256-cts-hmac-sha384-192"),
    (23, "rc4-hmac"),
    (24, "rc4-hmac-exp"),
    (25, "camellia128-cts-cmac"),
    (26, "camellia256-cts-cmac"),
    (65, "subkey-keymaterial"),
];

const CHECKSUM_TYPES: &[(i32, &str, usize)] = &[
    (1, "CRC32", 4),
    (2, "rsa-md4", 16),
    (3, "rsa-md4-des", 24),
    (4, "des-mac", 16),
    (5, "des-mac-k", 8),
    (6, "rsa-md4-des-k", 16),
    (7, "rsa-md5", 16),
    (8, "rsa-md5-des", 24),
    (9, "rsa-md5-des3", 24),
    (10, "sha1", 20),
    (12, "hmac-sha1-des3-kd", 20),
    (13, "hmac-sha1-des3", 20),
    (14, "sha1", 20),
    (17, "cmac-camellia128", 16),
    (18, "cmac-camellia256", 16),
    (19, "hmac-sha256-128-aes128", 16),
    (20, "hmac-sha384-192-aes256", 24),
];

#[test]
fn the_encryption_types_match_the_iana_registry() {
    assert_eq!(KerberosEncryptionType::ALL.len(), ENCRYPTION_TYPES.len());
    for &(number, name) in ENCRYPTION_TYPES {
        let encryption = KerberosEncryptionType::from_number(number).unwrap_or_else(|| panic!("{number} {name} is missing"));
        assert_eq!(encryption.as_str(), name);
        assert_eq!(KerberosEncryptionType::from_name(name), Some(encryption));
    }
    for number in [0, 4, 6, 8, 21, 22, 27, 64, 66, -1] {
        assert_eq!(KerberosEncryptionType::from_number(number), None, "{number}");
    }
}

#[test]
fn the_checksum_types_match_the_iana_registry_rfc3962_and_rfc4757() {
    assert_eq!(KerberosChecksumType::ALL.len(), CHECKSUM_TYPES.len() + 3);
    for &(number, name, size) in CHECKSUM_TYPES {
        let checksum = KerberosChecksumType::from_number(number).unwrap_or_else(|| panic!("{number} {name} is missing"));
        assert_eq!(checksum.as_str(), name);
        assert_eq!(checksum.size(), size, "{name}");
        if name != "sha1" {
            assert_eq!(KerberosChecksumType::from_name(name), Some(checksum));
        }
    }
    let sha1: Vec<KerberosChecksumType> = [10, 14].into_iter().map(|number| KerberosChecksumType::from_number(number).unwrap()).collect();
    assert!(sha1.contains(&KerberosChecksumType::from_name("sha1").unwrap()));
    for checksum in sha1 {
        assert_eq!((checksum.size(), checksum.keyed()), (20, false), "{}", checksum.number());
    }
    for (number, name) in [(15, "hmac-sha1-96-aes128"), (16, "hmac-sha1-96-aes256")] {
        let checksum = KerberosChecksumType::from_number(number).unwrap();
        assert_eq!(checksum.as_str(), name);
        assert_eq!(KerberosChecksumType::from_name(name), Some(checksum));
        assert_eq!(checksum.size() * 8, 96, "{name}");
    }
    let checksum = KerberosChecksumType::from_number(-138).unwrap();
    assert_eq!((checksum.as_str(), checksum.size(), checksum.keyed()), ("hmac-md5", 16, true));
    for number in [0, 11, 21, 32771] {
        assert_eq!(KerberosChecksumType::from_number(number), None, "{number}");
    }
}

#[test]
fn message_types_follow_rfc4120() {
    let expected = [(10, "KRB_AS_REQ"), (11, "KRB_AS_REP"), (12, "KRB_TGS_REQ"), (13, "KRB_TGS_REP"), (14, "KRB_AP_REQ"), (15, "KRB_AP_REP"), (20, "KRB_SAFE"), (21, "KRB_PRIV"), (22, "KRB_CRED"), (30, "KRB_ERROR")];
    assert_eq!(KerberosMessageType::ALL.len(), expected.len());
    for (number, name) in expected {
        let kind = KerberosMessageType::from_number(number).unwrap_or_else(|| panic!("{number} {name} is missing"));
        assert_eq!(kind.as_str(), name);
        assert_eq!(KerberosMessageType::from_name(name), Some(kind));
    }
}

#[test]
fn name_types_follow_rfc4120_and_rfc6111() {
    let expected = [(0, "NT-UNKNOWN"), (1, "NT-PRINCIPAL"), (2, "NT-SRV-INST"), (3, "NT-SRV-HST"), (4, "NT-SRV-XHST"), (5, "NT-UID"), (6, "NT-X500-PRINCIPAL"), (7, "NT-SMTP-NAME"), (10, "NT-ENTERPRISE"), (11, "NT-WELLKNOWN")];
    assert_eq!(KerberosNameType::ALL.len(), expected.len());
    for (number, name) in expected {
        let kind = KerberosNameType::from_number(number).unwrap_or_else(|| panic!("{number} {name} is missing"));
        assert_eq!(kind.as_str(), name);
        assert_eq!(KerberosNameType::from_name(name), Some(kind));
    }
}

#[test]
fn error_codes_follow_rfc4120_rfc4556_and_rfc6113() {
    let expected = [
        (0, "KDC_ERR_NONE"), (1, "KDC_ERR_NAME_EXP"), (2, "KDC_ERR_SERVICE_EXP"), (3, "KDC_ERR_BAD_PVNO"), (4, "KDC_ERR_C_OLD_MAST_KVNO"), (5, "KDC_ERR_S_OLD_MAST_KVNO"),
        (6, "KDC_ERR_C_PRINCIPAL_UNKNOWN"), (7, "KDC_ERR_S_PRINCIPAL_UNKNOWN"), (8, "KDC_ERR_PRINCIPAL_NOT_UNIQUE"), (9, "KDC_ERR_NULL_KEY"), (10, "KDC_ERR_CANNOT_POSTDATE"),
        (11, "KDC_ERR_NEVER_VALID"), (12, "KDC_ERR_POLICY"), (13, "KDC_ERR_BADOPTION"), (14, "KDC_ERR_ETYPE_NOSUPP"), (15, "KDC_ERR_SUMTYPE_NOSUPP"), (16, "KDC_ERR_PADATA_TYPE_NOSUPP"),
        (17, "KDC_ERR_TRTYPE_NOSUPP"), (18, "KDC_ERR_CLIENT_REVOKED"), (19, "KDC_ERR_SERVICE_REVOKED"), (20, "KDC_ERR_TGT_REVOKED"), (21, "KDC_ERR_CLIENT_NOTYET"), (22, "KDC_ERR_SERVICE_NOTYET"),
        (23, "KDC_ERR_KEY_EXPIRED"), (24, "KDC_ERR_PREAUTH_FAILED"), (25, "KDC_ERR_PREAUTH_REQUIRED"), (26, "KDC_ERR_SERVER_NOMATCH"), (27, "KDC_ERR_MUST_USE_USER2USER"),
        (28, "KDC_ERR_PATH_NOT_ACCEPTED"), (29, "KDC_ERR_SVC_UNAVAILABLE"), (31, "KRB_AP_ERR_BAD_INTEGRITY"), (32, "KRB_AP_ERR_TKT_EXPIRED"), (33, "KRB_AP_ERR_TKT_NYV"),
        (34, "KRB_AP_ERR_REPEAT"), (35, "KRB_AP_ERR_NOT_US"), (36, "KRB_AP_ERR_BADMATCH"), (37, "KRB_AP_ERR_SKEW"), (38, "KRB_AP_ERR_BADADDR"), (39, "KRB_AP_ERR_BADVERSION"),
        (40, "KRB_AP_ERR_MSG_TYPE"), (41, "KRB_AP_ERR_MODIFIED"), (42, "KRB_AP_ERR_BADORDER"), (44, "KRB_AP_ERR_BADKEYVER"), (45, "KRB_AP_ERR_NOKEY"), (46, "KRB_AP_ERR_MUT_FAIL"),
        (47, "KRB_AP_ERR_BADDIRECTION"), (48, "KRB_AP_ERR_METHOD"), (49, "KRB_AP_ERR_BADSEQ"), (50, "KRB_AP_ERR_INAPP_CKSUM"), (51, "KRB_AP_PATH_NOT_ACCEPTED"),
        (52, "KRB_ERR_RESPONSE_TOO_BIG"), (60, "KRB_ERR_GENERIC"), (61, "KRB_ERR_FIELD_TOOLONG"), (62, "KDC_ERROR_CLIENT_NOT_TRUSTED"), (63, "KDC_ERROR_KDC_NOT_TRUSTED"),
        (64, "KDC_ERROR_INVALID_SIG"), (65, "KDC_ERR_KEY_TOO_WEAK"), (66, "KDC_ERR_CERTIFICATE_MISMATCH"), (67, "KRB_AP_ERR_NO_TGT"), (68, "KDC_ERR_WRONG_REALM"),
        (69, "KRB_AP_ERR_USER_TO_USER_REQUIRED"), (70, "KDC_ERR_CANT_VERIFY_CERTIFICATE"), (71, "KDC_ERR_INVALID_CERTIFICATE"), (72, "KDC_ERR_REVOKED_CERTIFICATE"),
        (73, "KDC_ERR_REVOCATION_STATUS_UNKNOWN"), (74, "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE"), (75, "KDC_ERR_CLIENT_NAME_MISMATCH"), (76, "KDC_ERR_KDC_NAME_MISMATCH"),
        (77, "KDC_ERR_INCONSISTENT_KEY_PURPOSE"), (78, "KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED"), (79, "KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED"), (80, "KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED"),
        (81, "KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED"), (90, "KDC_ERR_PREAUTH_EXPIRED"), (91, "KDC_ERR_MORE_PREAUTH_DATA_REQUIRED"), (92, "KDC_ERR_PREAUTH_BAD_AUTHENTICATION_SET"),
        (93, "KDC_ERR_UNKNOWN_CRITICAL_FAST_OPTIONS"),
    ];
    assert_eq!(KerberosErrorCode::ALL.len(), expected.len());
    for (number, name) in expected {
        let code = KerberosErrorCode::from_number(number);
        assert_eq!(code.number(), number);
        assert_eq!(code.as_str(), name);
        assert_eq!(KerberosErrorCode::from_name(name), Some(code));
    }
    for number in [30, 43, 53, 59, 82, 89, 94, -1] {
        assert_eq!(KerberosErrorCode::from_number(number), KerberosErrorCode::Unknown(number), "{number}");
        assert_eq!(KerberosErrorCode::Unknown(number).number(), number);
    }
}
