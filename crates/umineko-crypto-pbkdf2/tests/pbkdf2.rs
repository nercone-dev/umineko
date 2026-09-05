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

impl umineko_crypto_pbkdf2::PRF for HMAC {
    fn output_size(&self) -> usize {
        32
    }

    fn compute(&self, key: &[u8], data: &[u8], output: &mut [u8]) {
        HMAC::compute(key, data, output);
    }
}

use umineko_crypto_pbkdf2::{PBKDF2Error, PBKDF2};

#[test]
fn vectors() {
    let mut output = [0; 64];
    PBKDF2::new(HMAC, 1).derive(b"passwd", b"salt", &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"));
    let mut output = [0; 32];
    PBKDF2::new(HMAC, 1).derive(b"password", b"salt", &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"));
    let mut output = [0; 32];
    PBKDF2::new(HMAC, 2).derive(b"password", b"salt", &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"));
    let mut output = [0; 32];
    PBKDF2::new(HMAC, 4096).derive(b"password", b"salt", &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"));
    let mut output = [0; 40];
    PBKDF2::new(HMAC, 4096).derive(b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"));
}

#[test]
fn verification() {
    let derivation = PBKDF2::new(HMAC, 1000);
    let mut output = [0; 32];
    derivation.derive(b"secret", b"salt", &mut output).unwrap();
    assert_eq!(derivation.verify(b"secret", b"salt", &output), Ok(()));
    assert_eq!(derivation.verify(b"other", b"salt", &output), Err(PBKDF2Error::Verification));
    assert_eq!(PBKDF2::new(HMAC, 0).derive(b"secret", b"salt", &mut output), Err(PBKDF2Error::Iterations));
}

use umineko_hash_hmac::HMACFunction;
use umineko_hash_sha::SHA1;

/// The cases of RFC 6070, less the one of sixteen million iterations, which key PBKDF2 with HMAC-SHA-1.
#[test]
fn the_keyed_hash_matches_rfc_6070() {
    let function = HMACFunction::<SHA1>::new();
    let mut output = [0; 20];
    PBKDF2::new(function, 1).derive(b"password", b"salt", &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("0c60c80f961f0e71f3a9b524af6012062fe037a6"));
    let mut output = [0; 20];
    PBKDF2::new(function, 2).derive(b"password", b"salt", &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"));
    let mut output = [0; 20];
    PBKDF2::new(function, 4096).derive(b"password", b"salt", &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("4b007901b765489abead49d926f721d065a429c1"));
    let mut output = [0; 25];
    PBKDF2::new(function, 4096).derive(b"passwordPASSWORDpassword", b"saltSALTsaltSALTsaltSALTsaltSALTsalt", &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"));
    let mut output = [0; 16];
    PBKDF2::new(function, 4096).derive(b"pass\0word", b"sa\0lt", &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("56fa6aa75548099dcc37d7f03425e0c3"));
}

/// The cases of RFC 7914 section 11, which the function of the keyed hash crate has to agree with.
#[test]
fn the_keyed_hash_matches_rfc_7914() {
    let function = HMACFunction::<SHA2_256>::new();
    let mut output = [0; 64];
    PBKDF2::new(function, 1).derive(b"passwd", b"salt", &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"));
    let mut output = [0; 64];
    PBKDF2::new(function, 80000).derive(b"Password", b"NaCl", &mut output).unwrap();
    assert_eq!(output.to_vec(), hex("4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"));
}

#[test]
fn the_keyed_hash_names_itself_and_its_hash() {
    let request = PBKDF2::new(HMACFunction::<SHA2_256>::new(), 1000).request().unwrap();
    assert_eq!(request.algorithm, "PBKDF2");
    assert_eq!(request.prf, Some("HMAC"));
    assert_eq!(request.digest, Some("SHA-256"));
    assert_eq!(request.iterations, 1000);
    assert_eq!(PBKDF2::new(HMAC, 1000).request(), None);
}
