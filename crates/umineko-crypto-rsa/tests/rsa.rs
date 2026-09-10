use umineko_crypto_rsa::{RSAEncryptionPadding, RSAHash, RSASignaturePadding};

#[test]
fn digest_info_prefixes_follow_rfc8017() {
    let expected: [(RSAHash, &[u8]); 9] = [
        (RSAHash::MD2, &[0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x02, 0x05, 0x00, 0x04, 0x10]),
        (RSAHash::MD5, &[0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10]),
        (RSAHash::SHA1, &[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14]),
        (RSAHash::SHA2_224, &[0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c]),
        (RSAHash::SHA2_256, &[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]),
        (RSAHash::SHA2_384, &[0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]),
        (RSAHash::SHA2_512, &[0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]),
        (RSAHash::SHA2_512_224, &[0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05, 0x05, 0x00, 0x04, 0x1c]),
        (RSAHash::SHA2_512_256, &[0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06, 0x05, 0x00, 0x04, 0x20]),
    ];
    for (hash, prefix) in expected {
        assert_eq!(hash.digest_info(), Some(prefix), "{hash}");
    }
}

#[test]
fn sha3_digest_info_uses_the_nist_hash_algorithm_arcs() {
    for (hash, arc, size) in [(RSAHash::SHA3_224, 0x07, 28), (RSAHash::SHA3_256, 0x08, 32), (RSAHash::SHA3_384, 0x09, 48), (RSAHash::SHA3_512, 0x0a, 64)] {
        let mut expected = vec![0x30, 17 + size as u8, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, arc, 0x05, 0x00, 0x04, size as u8];
        assert_eq!(hash.digest_info(), Some(expected.as_slice()), "{hash}");
        expected.clear();
        assert_eq!(hash.digest_size(), size, "{hash}");
    }
}

#[test]
fn digest_info_lengths_are_consistent_der() {
    for hash in RSAHash::ALL {
        assert_eq!(RSAHash::from_name(hash.as_str()), Some(hash));
        match hash.digest_info() {
            Some(prefix) => {
                assert_eq!(prefix[1] as usize, prefix.len() - 2 + hash.digest_size(), "{hash}");
                assert_eq!(&prefix[prefix.len() - 2..], &[0x04, hash.digest_size() as u8], "{hash}");
            }
            None => assert_eq!(hash, RSAHash::MD5_SHA1),
        }
    }
    assert_eq!(RSAHash::MD5_SHA1.digest_size(), 16 + 20);
}

#[test]
fn maximum_message_lengths_follow_rfc8017() {
    assert_eq!(RSAEncryptionPadding::PKCS1V15.maximum_length(256), Some(245));
    assert_eq!(RSAEncryptionPadding::PKCS1V15.maximum_length(11), Some(0));
    assert_eq!(RSAEncryptionPadding::PKCS1V15.maximum_length(10), None);
    let oaep = RSAEncryptionPadding::OAEP { hash: RSAHash::SHA2_256, mask: RSAHash::SHA2_256 };
    assert_eq!(oaep.maximum_length(256), Some(190));
    assert_eq!(oaep.maximum_length(66), Some(0));
    assert_eq!(oaep.maximum_length(65), None);
    assert_eq!(RSAEncryptionPadding::OAEP { hash: RSAHash::SHA1, mask: RSAHash::SHA1 }.maximum_length(128), Some(86));
}

#[test]
fn provider_requests_carry_the_hash_mask_and_salt_parameters() {
    let request = RSASignaturePadding::PSS { hash: RSAHash::SHA2_384, mask: RSAHash::SHA2_256, salt_size: 48 }.request(&[]);
    assert_eq!((request.algorithm, request.digest, request.mask, request.salt_size), ("RSA-PSS", Some("SHA-384"), Some("SHA-256"), Some(48)));
    let request = RSASignaturePadding::PKCS1V15(RSAHash::MD5_SHA1).request(&[]);
    assert_eq!((request.algorithm, request.digest, request.mask, request.salt_size), ("RSA-PKCS1v15", Some("MD5-SHA1"), None, None));
    let request = RSAEncryptionPadding::OAEP { hash: RSAHash::SHA2_512, mask: RSAHash::SHA1 }.request(&[1], b"label");
    assert_eq!((request.algorithm, request.digest, request.mask, request.associated), ("RSA-OAEP", Some("SHA-512"), Some("SHA-1"), &b"label"[..]));
    let request = RSAEncryptionPadding::PKCS1V15.request(&[1], &[]);
    assert_eq!((request.algorithm, request.digest, request.mask), ("RSA-PKCS1v15", None, None));
}
