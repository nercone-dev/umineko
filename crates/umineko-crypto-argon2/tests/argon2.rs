use umineko_crypto_argon2::{Argon2, Argon2Error, Argon2Variant};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap()).collect()
}

fn parameters(variant: Argon2Variant) -> Argon2 {
    Argon2 { variant, version: Argon2::VERSION_13, memory: 32, iterations: 3, parallelism: 4 }
}

#[test]
fn vectors() {
    for (variant, expected) in [
        (Argon2Variant::D, "512b391b6f1162975371d3091973429 4f868e3be3984f3c1a13a4db9fabe4acb".replace(' ', "")),
        (Argon2Variant::I, "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8".into()),
        (Argon2Variant::ID, "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659".into()),
    ] {
        let mut output = [0; 32];
        parameters(variant).derive(&[1; 32], &[2; 16], &[3; 8], &[4; 12], &mut output).unwrap();
        assert_eq!(output.to_vec(), hex(&expected), "{variant}");
    }
}

#[test]
fn parameter_failures() {
    let mut output = [0; 32];
    assert_eq!(Argon2::default().derive(&[1; 32], &[2; 7], &[], &[], &mut output), Err(Argon2Error::Salt));
    let derivation = Argon2 { parallelism: 0, ..Argon2::default() };
    assert_eq!(derivation.derive(&[1; 32], &[2; 16], &[], &[], &mut output), Err(Argon2Error::Parameters));
    let derivation = Argon2 { iterations: 0, ..Argon2::default() };
    assert_eq!(derivation.derive(&[1; 32], &[2; 16], &[], &[], &mut output), Err(Argon2Error::Parameters));
    let derivation = Argon2 { version: 0x11, ..Argon2::default() };
    assert_eq!(derivation.derive(&[1; 32], &[2; 16], &[], &[], &mut output), Err(Argon2Error::Parameters));
    let derivation = Argon2 { memory: 8, parallelism: 4, ..Argon2::default() };
    assert_eq!(derivation.derive(&[1; 32], &[2; 16], &[], &[], &mut output), Err(Argon2Error::Parameters));
    let mut short = [0; 3];
    assert_eq!(parameters(Argon2Variant::ID).derive(&[1; 32], &[2; 16], &[], &[], &mut short), Err(Argon2Error::Length));
}

#[test]
fn tag_lengths() {
    for length in [4, 16, 31, 32, 64, 65, 100, 1024] {
        let mut output = alloc_zero(length);
        parameters(Argon2Variant::ID).derive(b"password", b"somesalt", &[], &[], &mut output).unwrap();
        assert!(output.iter().any(|byte| *byte != 0), "{length}");
        let mut again = alloc_zero(length);
        parameters(Argon2Variant::ID).derive(b"password", b"somesalt", &[], &[], &mut again).unwrap();
        assert_eq!(output, again, "{length}");
    }
}

#[test]
fn verification() {
    let derivation = parameters(Argon2Variant::ID);
    let mut output = [0; 32];
    derivation.derive(b"password", b"somesalt", &[], &[], &mut output).unwrap();
    assert_eq!(derivation.verify(b"password", b"somesalt", &[], &[], &output), Ok(()));
    assert_eq!(derivation.verify(b"other", b"somesalt", &[], &[], &output), Err(Argon2Error::Verification));
}

fn alloc_zero(length: usize) -> Vec<u8> {
    (0..length).map(|_| 0).collect()
}
