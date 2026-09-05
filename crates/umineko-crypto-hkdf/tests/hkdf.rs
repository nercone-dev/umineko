use umineko_hash_sha::SHA2_256;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap()).collect()
}

struct HMAC;

impl HMAC {
    const BLOCK_SIZE: usize = 64;

    fn pad(key: &[u8], value: u8) -> [u8; 64] {
        let mut block = [value; Self::BLOCK_SIZE];
        let key = match key.len() > Self::BLOCK_SIZE {
            true => SHA2_256::digest(key).to_vec(),
            false => key.to_vec(),
        };
        for (byte, source) in block.iter_mut().zip(&key) {
            *byte ^= source;
        }
        block
    }

    fn compute(key: &[u8], data: &[u8], output: &mut [u8]) {
        let mut inner = SHA2_256::builtin();
        inner.update(&Self::pad(key, 0x36));
        inner.update(data);
        let mut outer = SHA2_256::builtin();
        outer.update(&Self::pad(key, 0x5c));
        outer.update(&inner.finalize());
        output.copy_from_slice(&outer.finalize()[..output.len()]);
    }
}

impl umineko_crypto_hkdf::PRF for HMAC {
    fn output_size(&self) -> usize {
        32
    }

    fn compute(&self, key: &[u8], data: &[u8], output: &mut [u8]) {
        HMAC::compute(key, data, output);
    }
}

use umineko_crypto_hkdf::{HKDFError, HKDF};

#[test]
fn vectors() {
    let hkdf = HKDF::new(HMAC);
    let material = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let key = hkdf.extract(&hex("000102030405060708090a0b0c"), &material);
    assert_eq!(key, hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
    let mut output = [0; 42];
    hkdf.expand(&key, &hex("f0f1f2f3f4f5f6f7f8f9"), &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
    let key = hkdf.extract(&[], &material);
    assert_eq!(key, hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"));
    let mut output = [0; 42];
    hkdf.expand(&key, &[], &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"));
    let mut derived = [0; 42];
    hkdf.derive(&[], &material, &[], &mut derived).unwrap();
    assert_eq!(derived, output);
}

#[test]
fn long_vector() {
    let hkdf = HKDF::new(HMAC);
    let material: Vec<u8> = (0..80).collect();
    let salt: Vec<u8> = (0x60..0xb0).collect();
    let info: Vec<u8> = (0xb0..0x100).map(|value| value as u8).collect();
    let key = hkdf.extract(&salt, &material);
    assert_eq!(key, hex("06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244"));
    let mut output = [0; 82];
    hkdf.expand(&key, &info, &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"));
}

#[test]
fn limits() {
    let hkdf = HKDF::new(HMAC);
    let mut output = [0; 32 * 255 + 1];
    assert_eq!(hkdf.expand(&[0; 32], &[], &mut output), Err(HKDFError::Length));
    let mut output = [0; 32 * 255];
    assert_eq!(hkdf.expand(&[0; 32], &[], &mut output), Ok(()));
}

use umineko_hash_hmac::HMACFunction;
use umineko_hash_sha::SHA1;

/// The four cases of RFC 5869 appendix A that key HKDF with HMAC-SHA-1.
#[test]
fn the_keyed_hash_matches_rfc_5869_over_sha1() {
    let hkdf = HKDF::new(HMACFunction::<SHA1>::new());
    let key = hkdf.extract(&hex("000102030405060708090a0b0c"), &hex("0b0b0b0b0b0b0b0b0b0b0b"));
    assert_eq!(key, hex("9b6c18c432a7bf8f0e71c8eb88f4b30baa2ba243"));
    let mut output = [0; 42];
    hkdf.expand(&key, &hex("f0f1f2f3f4f5f6f7f8f9"), &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896"));

    let material: Vec<u8> = (0..80).collect();
    let salt: Vec<u8> = (0x60..0xb0).collect();
    let info: Vec<u8> = (0xb0..0x100).map(|value| value as u8).collect();
    let key = hkdf.extract(&salt, &material);
    assert_eq!(key, hex("8adae09a2a307059478d309b26c4115a224cfaf6"));
    let mut output = [0; 82];
    hkdf.expand(&key, &info, &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4"));

    let key = hkdf.extract(&[], &hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"));
    assert_eq!(key, hex("da8c8a73c7fa77288ec6f5e7c297786aa0d32d01"));
    let mut output = [0; 42];
    hkdf.expand(&key, &[], &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918"));

    let key = hkdf.extract(&[0; 20], &hex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"));
    assert_eq!(key, hex("2adccada18779e7c2077ad2eb19d3f3e731385dd"));
    let mut output = [0; 42];
    hkdf.expand(&key, &[], &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48"));
}

/// The first two cases of RFC 5869 appendix A, which the function of the keyed hash crate has to agree with.
#[test]
fn the_keyed_hash_matches_rfc_5869_over_sha2_256() {
    let hkdf = HKDF::new(HMACFunction::<SHA2_256>::new());
    let material = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let key = hkdf.extract(&hex("000102030405060708090a0b0c"), &material);
    assert_eq!(key, hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
    let mut output = [0; 42];
    hkdf.expand(&key, &hex("f0f1f2f3f4f5f6f7f8f9"), &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"));
    let key = hkdf.extract(&[], &material);
    assert_eq!(key, hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"));
    let mut output = [0; 42];
    hkdf.expand(&key, &[], &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"));
}

#[test]
fn the_keyed_hash_names_itself_and_its_hash() {
    let request = HKDF::new(HMACFunction::<SHA2_256>::new()).request("HKDF").unwrap();
    assert_eq!(request.algorithm, "HKDF");
    assert_eq!(request.prf, Some("HMAC"));
    assert_eq!(request.digest, Some("SHA-256"));
    assert_eq!(HKDF::new(HMACFunction::<SHA1>::new()).request("HKDF").unwrap().digest, Some("SHA-1"));
    assert_eq!(HKDF::new(HMAC).request("HKDF"), None);
}
