use umineko_crypto_gost::{GOST28147, GOST28147KeyMeshing, GOST28147Mode, GOST28147SBox, GOSTMode, Kuznyechik, Magma};

#[test]
fn block_ciphers_follow_rfc7801_rfc8891_and_rfc5830() {
    assert_eq!((Kuznyechik::KEY_SIZE, Kuznyechik::BLOCK_SIZE), (32, 16));
    assert_eq!((Magma::KEY_SIZE, Magma::BLOCK_SIZE), (32, 8));
    assert_eq!((GOST28147::KEY_SIZE, GOST28147::BLOCK_SIZE), (32, 8));
}

#[test]
fn key_meshing_follows_rfc4357_and_rfc9189() {
    let constant = [0x69, 0x00, 0x72, 0x22, 0x64, 0xC9, 0x04, 0x23, 0x8D, 0x3A, 0xDB, 0x96, 0x46, 0xE9, 0x2A, 0xC4, 0x18, 0xFE, 0xAC, 0x94, 0x00, 0xED, 0x07, 0x12, 0xC0, 0x86, 0xDC, 0xC2, 0xEF, 0x4C, 0xA9, 0x2B];
    assert_eq!(GOST28147KeyMeshing::CRYPTOPRO_KEY, constant);
    assert_eq!(GOST28147KeyMeshing::CryptoPro.interval(), Some(1024));
    assert_eq!(GOST28147KeyMeshing::None.interval(), None);
    for (meshing, name) in [(GOST28147KeyMeshing::None, "id-Gost28147-89-None-KeyMeshing"), (GOST28147KeyMeshing::CryptoPro, "id-Gost28147-89-CryptoPro-KeyMeshing")] {
        assert_eq!(meshing.as_str(), name);
        assert_eq!(GOST28147KeyMeshing::from_name(name), Some(meshing));
    }
    for sbox in [GOST28147SBox::TC26Z, GOST28147SBox::CryptoProA, GOST28147SBox::CryptoProB, GOST28147SBox::CryptoProC, GOST28147SBox::CryptoProD] {
        assert_eq!(sbox.key_meshing(), GOST28147KeyMeshing::CryptoPro, "{sbox}");
    }
}

#[test]
fn key_export_sizes_follow_rfc9189() {
    assert_eq!(GOST28147::UKM_SIZE, 8);
    assert_eq!(GOST28147::EXPORT_SIZE, GOST28147::UKM_SIZE + GOST28147::KEY_SIZE + GOST28147::MAC_SIZE);
    assert_eq!(GOST28147::EXPORT_SIZE, 44);
}

#[test]
fn mac_sizes_follow_rfc9189() {
    assert_eq!(Kuznyechik::MAC_SIZE, 16);
    assert_eq!(Magma::MAC_SIZE, 8);
    assert_eq!(GOST28147::MAC_SIZE, 4);
}

#[test]
fn counter_nonces_are_half_a_block_by_rfc9189() {
    assert_eq!(Kuznyechik::nonce_size(GOSTMode::CTR_ACPKM), Some(8));
    assert_eq!(Magma::nonce_size(GOSTMode::CTR_ACPKM), Some(4));
    assert_eq!(Kuznyechik::nonce_size(GOSTMode::CTR), Some(8));
    assert_eq!(Magma::nonce_size(GOSTMode::CTR), Some(4));
    assert_eq!(Kuznyechik::nonce_size(GOSTMode::ECB), None);
    assert_eq!(Magma::nonce_size(GOSTMode::ECB), None);
}

#[test]
fn mgm_nonces_and_tags_are_one_block_by_rfc9367() {
    assert_eq!((Kuznyechik::nonce_size(GOSTMode::MGM), Kuznyechik::tag_size(GOSTMode::MGM)), (Some(16), Some(16)));
    assert_eq!((Magma::nonce_size(GOSTMode::MGM), Magma::tag_size(GOSTMode::MGM)), (Some(8), Some(8)));
    for mode in [GOSTMode::ECB, GOSTMode::CBC, GOSTMode::CFB, GOSTMode::OFB, GOSTMode::CTR, GOSTMode::CTR_ACPKM] {
        assert_eq!(Kuznyechik::tag_size(mode), None);
        assert_eq!(Magma::tag_size(mode), None);
        assert!(!mode.authenticated());
    }
    assert!(GOSTMode::MGM.authenticated());
}

#[test]
fn provider_names_are_distinct() {
    let mut names = Vec::new();
    for mode in [GOSTMode::ECB, GOSTMode::CBC, GOSTMode::CFB, GOSTMode::OFB, GOSTMode::CTR, GOSTMode::CTR_ACPKM, GOSTMode::MGM] {
        names.push(Kuznyechik::name(mode));
        names.push(Magma::name(mode));
    }
    for sbox in [GOST28147SBox::TC26Z, GOST28147SBox::CryptoProA, GOST28147SBox::CryptoProB, GOST28147SBox::CryptoProC, GOST28147SBox::CryptoProD] {
        assert_eq!(GOST28147SBox::from_name(sbox.as_str()), Some(sbox));
        names.push(GOST28147::mac_name(sbox));
        for mode in [GOST28147Mode::ECB, GOST28147Mode::CNT, GOST28147Mode::CFB] {
            names.push(GOST28147::name(mode, sbox));
        }
    }
    let count = names.len();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), count);
}

#[test]
fn ctr_acpkm_section_sizes_are_divisible_by_the_block_size_by_rfc8645() {
    let key = [0x42; 32];
    let kuznyechik = Kuznyechik::new(GOSTMode::CTR_ACPKM, &key);
    assert_eq!(kuznyechik.section_size(), None);
    assert_eq!(kuznyechik.request(&[], &[]).section_size, None);
    let kuznyechik = kuznyechik.with_section_size(4096).unwrap();
    assert_eq!(kuznyechik.section_size(), Some(4096));
    assert_eq!(kuznyechik.request(&[], &[]).section_size, Some(4096));
    for size in [0, 8, 4095, 4100] {
        assert!(Kuznyechik::new(GOSTMode::CTR_ACPKM, &key).with_section_size(size).is_err(), "{size}");
    }
    let magma = Magma::new(GOSTMode::CTR_ACPKM, &key);
    assert_eq!(magma.section_size(), None);
    let magma = magma.with_section_size(1024).unwrap();
    assert_eq!(magma.section_size(), Some(1024));
    assert_eq!(magma.request(&[], &[]).section_size, Some(1024));
    assert_eq!(Magma::new(GOSTMode::CTR_ACPKM, &key).with_section_size(8).map(|magma| magma.section_size()), Ok(Some(8)));
    for size in [0, 4, 1020, 1025] {
        assert!(Magma::new(GOSTMode::CTR_ACPKM, &key).with_section_size(size).is_err(), "{size}");
    }
}
