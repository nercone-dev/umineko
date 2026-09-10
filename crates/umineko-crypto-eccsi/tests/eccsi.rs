use umineko_crypto_eccsi::{ECCSI, ECCSIError, ECCSIPublicKey, ECCSISignature, ECCSISigningKey};

#[test]
fn the_mikey_sakke_profile_follows_rfc6509() {
    assert_eq!(ECCSI::P256.curve_name(), "secp256r1");
    assert_eq!(ECCSI::P256.hash_name(), "SHA-256");
    assert_eq!(ECCSI::P256.security_bits(), 256);
    assert_eq!(ECCSI::from_name(ECCSI::P256.as_str()), Some(ECCSI::P256));
}

#[test]
fn material_sizes_follow_rfc6507() {
    let variant = ECCSI::P256;
    let n = 32;
    assert_eq!(variant.field_size(), n);
    assert_eq!(variant.point_size(), 2 * n + 1);
    assert_eq!(variant.master_key_size(), n);
    assert_eq!(variant.public_key_size(), 2 * n + 1);
    assert_eq!(variant.secret_signing_key_size(), n);
    assert_eq!(variant.public_validation_token_size(), 2 * n + 1);
    assert_eq!(variant.signature_size(), 4 * n + 1);
}

#[test]
fn points_are_uncompressed_by_rfc6507() {
    let mut point = vec![0x04; 65];
    assert!(ECCSIPublicKey::decode(ECCSI::P256, &point).is_ok());
    point[0] = 0x02;
    assert_eq!(ECCSIPublicKey::decode(ECCSI::P256, &point), Err(ECCSIError::Encoding));
    assert_eq!(ECCSIPublicKey::decode(ECCSI::P256, &point[..33]), Err(ECCSIError::Length));
    assert!(ECCSISigningKey::decode(ECCSI::P256, &[1; 32], &[0x04; 65]).is_ok());
    assert_eq!(ECCSISigningKey::decode(ECCSI::P256, &[1; 32], &point), Err(ECCSIError::Encoding));
    assert_eq!(ECCSISigningKey::decode(ECCSI::P256, &[1; 31], &[0x04; 65]), Err(ECCSIError::Length));
}

#[test]
fn signatures_are_r_s_and_pvt_by_rfc6507() {
    let mut data = vec![0; 129];
    data[..32].fill(0x11);
    data[32..64].fill(0x22);
    data[64] = 0x04;
    data[65..].fill(0x33);
    let signature = ECCSISignature::decode(ECCSI::P256, &data).unwrap();
    assert_eq!(signature.r(), &[0x11; 32]);
    assert_eq!(signature.s(), &[0x22; 32]);
    assert_eq!(signature.public_validation_token().len(), 65);
    assert_eq!(signature.public_validation_token()[0], 0x04);
    assert_eq!(signature.encode(), data);
    data[64] = 0x03;
    assert_eq!(ECCSISignature::decode(ECCSI::P256, &data), Err(ECCSIError::Encoding));
    assert_eq!(ECCSISignature::decode(ECCSI::P256, &data[..128]), Err(ECCSIError::Length));
}
