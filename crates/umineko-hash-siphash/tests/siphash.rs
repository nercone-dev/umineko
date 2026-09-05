use umineko_hash_siphash::{SipHash, SipHashRounds};

const KEY: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

#[test]
fn siphash_2_4_matches_the_reference_vectors() {
    let expected: [u64; 16] = [
        0x726F_DB47_DD0E_0E31,
        0x74F8_39C5_93DC_67FD,
        0x0D6C_8009_D9A9_4F5A,
        0x8567_6696_D7FB_7E2D,
        0xCF27_94E0_2771_87B7,
        0x1876_5564_CD99_A68D,
        0xCBC9_466E_58FE_E3CE,
        0xAB02_00F5_8B01_D137,
        0x93F5_F579_9A93_2462,
        0x9E00_82DF_0BA9_E4B0,
        0x7A5D_BBC5_94DD_B9F3,
        0xF4B3_2F46_226B_ADA7,
        0x751E_8FBC_860E_E5FB,
        0x14EA_5627_C084_3D90,
        0xF723_CA90_8E7A_F2EE,
        0xA129_CA61_49BE_45E5,
    ];
    for (length, digest) in expected.iter().enumerate() {
        let data: Vec<u8> = (0..length as u8).collect();
        assert_eq!(SipHash::digest(SipHashRounds::SIPHASH_2_4, &KEY, &data), *digest, "at {length}");
    }
}

#[test]
fn streaming_matches_the_one_shot_call() {
    let data: [u8; 256] = core::array::from_fn(|index| index as u8);
    for rounds in [SipHashRounds::SIPHASH_2_4, SipHashRounds::SIPHASH_1_3, SipHashRounds { compression: 4, finalization: 8 }] {
        for split in [0, 1, 7, 8, 9, 255, 256] {
            let mut hash = SipHash::new(rounds, &KEY);
            hash.update(&data[..split]);
            hash.update(&data[split..]);
            assert_eq!(hash.finalize(), SipHash::digest(rounds, &KEY, &data), "{rounds} at {split}");
        }
    }
}

#[test]
fn reset_restores_the_keyed_state() {
    let mut hash = SipHash::new(SipHashRounds::SIPHASH_2_4, &KEY);
    hash.update(b"discarded");
    hash.reset();
    assert_eq!(hash.finalize(), SipHash::digest(SipHashRounds::SIPHASH_2_4, &KEY, b""));
}
