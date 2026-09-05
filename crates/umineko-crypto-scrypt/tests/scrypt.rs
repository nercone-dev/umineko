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

impl umineko_crypto_scrypt::PRF for HMAC {
    fn output_size(&self) -> usize {
        32
    }

    fn compute(&self, key: &[u8], data: &[u8], output: &mut [u8]) {
        HMAC::compute(key, data, output);
    }
}

use umineko_crypto_scrypt::{Scrypt, ScryptError};

#[test]
fn vectors() {
    let mut output = [0; 64];
    Scrypt::new(HMAC, 16, 1, 1).unwrap().derive(b"", b"", &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"));
    let mut output = [0; 64];
    Scrypt::new(HMAC, 1024, 8, 16).unwrap().derive(b"password", b"NaCl", &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"));
    let mut output = [0; 64];
    Scrypt::new(HMAC, 16384, 8, 1).unwrap().derive(b"pleaseletmein", b"SodiumChloride", &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"));
}

#[test]
fn parameters() {
    assert_eq!(Scrypt::new(HMAC, 0, 1, 1).err(), Some(ScryptError::Cost));
    assert_eq!(Scrypt::new(HMAC, 1, 1, 1).err(), Some(ScryptError::Cost));
    assert_eq!(Scrypt::new(HMAC, 12, 1, 1).err(), Some(ScryptError::Cost));
    assert_eq!(Scrypt::new(HMAC, 16, 0, 1).err(), Some(ScryptError::Parameters));
    assert_eq!(Scrypt::new(HMAC, 16, 1, 0).err(), Some(ScryptError::Parameters));
    assert_eq!(Scrypt::new(HMAC, 16, 1, 1).unwrap().memory(), 2048);
}

#[test]
fn verification() {
    let derivation = Scrypt::new(HMAC, 16, 1, 1).unwrap();
    let mut output = [0; 32];
    derivation.derive(b"secret", b"salt", &mut output).unwrap();
    assert_eq!(derivation.verify(b"secret", b"salt", &output), Ok(()));
    assert_eq!(derivation.verify(b"other", b"salt", &output), Err(ScryptError::Verification));
    assert_eq!(derivation.derive(b"secret", b"salt", &mut []), Err(ScryptError::Length));
}

use umineko_hash_hmac::HMACFunction;

/// The cases of RFC 7914 section 12, less the one of a gigabyte, which the function of the keyed hash crate has to agree with.
#[test]
fn the_keyed_hash_matches_rfc_7914() {
    let function = HMACFunction::<SHA2_256>::new();
    let mut output = [0; 64];
    Scrypt::new(function, 16, 1, 1).unwrap().derive(b"", b"", &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906"));
    let mut output = [0; 64];
    Scrypt::new(function, 1024, 8, 16).unwrap().derive(b"password", b"NaCl", &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b3731622eaf30d92e22a3886ff109279d9830dac727afb94a83ee6d8360cbdfa2cc0640"));
    let mut output = [0; 64];
    Scrypt::new(function, 16384, 8, 1).unwrap().derive(b"pleaseletmein", b"SodiumChloride", &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887"));
}

#[test]
fn the_keyed_hash_names_itself_and_its_hash() {
    let request = Scrypt::new(HMACFunction::<SHA2_256>::new(), 16, 1, 1).unwrap().request().unwrap();
    assert_eq!(request.algorithm, "scrypt");
    assert_eq!(request.prf, Some("HMAC"));
    assert_eq!(request.digest, Some("SHA-256"));
    assert_eq!((request.cost, request.block, request.parallelism), (16, 1, 1));
    assert_eq!(Scrypt::new(HMAC, 16, 1, 1).unwrap().request(), None);
}
