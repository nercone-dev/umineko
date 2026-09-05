use umineko_crypto_slhdsa::{SLHDSA, SLHDSAError, SLHDSAPrivateKey, SLHDSAPublicKey, SLHDSASignature};
use umineko_hash_sha::SHA3_256;

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap()).collect()
}

fn message() -> Vec<u8> {
    (0..32).collect()
}

#[test]
fn vectors() {
    for (variant, seed, root, signature) in [
        (SLHDSA::SHA2_128F,
         "f0892a394c1fcf33d88a3302fa67273880f6f6df123013c0abb4a1789271478e7c8adad16a3159e46f6ee2d055be2be3",
         "2c63f9da004ea76d25022548084e006f",
         "4a4c94cac402eda31687126e91cfd3e4c53990e062b1d82c29f3f0976e14c43e"),
        (SLHDSA::SHAKE_128F,
         "f93c90712bcc5b67a06fc32dd6f199f317e272555f46365a63ef0dd43ca2692d5546e3bfc3ace41058e11b0c8421469b",
         "bfe32b2803cb9cf4a58efb6d7887d102",
         "6975b922dfff756d991e7688afe1c87a74cdde41144fb496cdbc55485b122979"),
        (SLHDSA::SHA2_192F,
         "d5d4720dd93a15922a7869913d18fd6993db7394a0901af245ef774d7529d5af4fd6feeeeed463a86a18c19aeadae602be716262dd19bdfe51c958626bd0d12a8a57a0610d74278e",
         "f5dd56d327ed9d5bbf876c3911342072890664636da37d08",
         "cc3213a18dbb47a6cec53efd737077cd1157b20f82cf456ef4047504b9d524ec"),
        (SLHDSA::SHAKE_256F,
         "7cae4dca96d64f936543f4782275c06e904c7aa82889a4e46b10ddc5eea789a913bf9da839e1426d8da1f88b021aef58afa325b52f4b824f2bc54316b883e3118abed62ba0c81cb2a2817403a4ba94481a1856a79c9b60604c082805dbac735f",
         "ef27cac44db06114b6cd2638dcea5fb6cd8f459b704a3f3b34109d4292630465",
         "3521c00395e1820fdbab7f745681f33b2aa6f700a4d10b30ff0e361fa807a46c"),
        (SLHDSA::SHA2_128S,
         "26174bcbffcf34d60fbe0c7bec7c37eb177868a3b59a9deb2911c3523bda2ef88fdc196afa96e67c1b489b3c29e2c0ce",
         "707ce7011f29ea00381ad26302f4b7d0",
         "b0222503b1677251682ad73efa7c1c3acff8299f490319e087638080e6871441"),
    ] {
        let (private, public) = variant.generate(&hex(seed)).unwrap();
        assert_eq!(public.encode().len(), variant.public_key_size(), "{variant}");
        assert_eq!(private.encode().len(), variant.private_key_size(), "{variant}");
        assert_eq!(public.encode()[variant.size()..], hex(root)[..], "{variant}");
        let produced = variant.produce(&private.encode(), &message());
        assert_eq!(produced.len(), variant.signature_size(), "{variant}");
        assert_eq!(SHA3_256::digest(&produced).to_vec(), hex(signature), "{variant}");
        assert!(variant.confirm(&public.encode(), &message(), &produced), "{variant}");
    }
}

#[test]
fn sizes() {
    for variant in SLHDSA::ALL {
        assert_eq!(variant.height() % variant.layers(), 0, "{variant}");
        assert_eq!(variant.public_key_size(), 2 * variant.size(), "{variant}");
        assert_eq!(variant.private_key_size(), 4 * variant.size(), "{variant}");
        assert_eq!(variant.seed_size(), 3 * variant.size(), "{variant}");
        assert_eq!(SLHDSA::from_name(variant.as_str()), Some(variant), "{variant}");
    }
    assert_eq!(SLHDSA::SHA2_128S.signature_size(), 7856);
    assert_eq!(SLHDSA::SHA2_128F.signature_size(), 17088);
    assert_eq!(SLHDSA::SHAKE_192S.signature_size(), 16224);
    assert_eq!(SLHDSA::SHAKE_256F.signature_size(), 49856);
    assert_eq!(SLHDSA::from_name("nothing"), None);
}

#[test]
fn round_trip() {
    for variant in [SLHDSA::SHA2_128F, SLHDSA::SHA2_192F, SLHDSA::SHA2_256F, SLHDSA::SHAKE_128F, SLHDSA::SHAKE_192F, SLHDSA::SHAKE_256F] {
        let seed: Vec<u8> = (0..variant.seed_size()).map(|index| index as u8).collect();
        let (private, public) = variant.generate(&seed).unwrap();
        assert_eq!(private.public_key(), public, "{variant}");
        let signature = private.sign(&message(), b"context").unwrap();
        assert_eq!(signature.encode().len(), variant.signature_size(), "{variant}");
        assert_eq!(public.verify(&message(), &signature, b"context"), Ok(()), "{variant}");
        assert_eq!(public.verify(&message(), &signature, &[]), Err(SLHDSAError::Verification), "{variant}");
        assert_eq!(public.verify(&message()[..31], &signature, b"context"), Err(SLHDSAError::Verification), "{variant}");
        let decoded = SLHDSASignature::decode(variant, &signature.encode()).unwrap();
        assert_eq!(public.verify(&message(), &decoded, b"context"), Ok(()), "{variant}");
        assert_eq!(SLHDSAPrivateKey::decode(variant, &private.encode()).unwrap(), private, "{variant}");
        assert_eq!(SLHDSAPublicKey::decode(variant, &public.encode()).unwrap(), public, "{variant}");
    }
}

#[test]
fn slow_round_trip() {
    for variant in [SLHDSA::SHA2_128S, SLHDSA::SHAKE_128S] {
        let seed: Vec<u8> = (0..variant.seed_size()).map(|index| index as u8).collect();
        let (private, public) = variant.generate(&seed).unwrap();
        let signature = private.sign(&message(), &[]).unwrap();
        assert_eq!(public.verify(&message(), &signature, &[]), Ok(()), "{variant}");
    }
}

#[test]
fn failures() {
    let variant = SLHDSA::SHA2_128F;
    assert_eq!(variant.generate(&[0; 8]).err(), Some(SLHDSAError::Seed));
    assert_eq!(SLHDSAPrivateKey::decode(variant, &[0; 8]).err(), Some(SLHDSAError::Encoding));
    assert_eq!(SLHDSAPublicKey::decode(variant, &[0; 8]).err(), Some(SLHDSAError::Encoding));
    assert_eq!(SLHDSASignature::decode(variant, &[0; 8]).err(), Some(SLHDSAError::Encoding));
    let seed: Vec<u8> = (0..variant.seed_size()).map(|index| index as u8).collect();
    let (private, public) = variant.generate(&seed).unwrap();
    assert_eq!(private.sign(&message(), &[0; 256]).err(), Some(SLHDSAError::Length));
    let signature = private.sign(&message(), &[]).unwrap();
    assert_eq!(public.verify(&message(), &signature, &[0; 256]), Err(SLHDSAError::Length));
    let other = SLHDSASignature::decode(SLHDSA::SHAKE_128F, &[0; 17088]).unwrap();
    assert_eq!(public.verify(&message(), &other, &[]), Err(SLHDSAError::Variant));
    let empty = SLHDSASignature::decode(variant, &[0; 17088]).unwrap();
    assert_eq!(public.verify(&message(), &empty, &[]), Err(SLHDSAError::Verification));
}
