use umineko_hash_crc::{Adler32, CRC16, CRC16Parameters, CRC32, CRC32C, CRC32Parameters};

const CHECK: &[u8] = b"123456789";

#[test]
fn crc16_matches_the_catalogue() {
    assert_eq!(CRC16::digest(CRC16Parameters::IBM, CHECK), 0xBB3D);
    assert_eq!(CRC16::digest(CRC16Parameters::CCITT, CHECK), 0x29B1);
    assert_eq!(CRC16::digest(CRC16Parameters::MODBUS, CHECK), 0x4B37);
}

#[test]
fn crc32_matches_the_catalogue() {
    assert_eq!(CRC32::digest(CRC32Parameters::IEEE, CHECK), 0xCBF4_3926);
    assert_eq!(CRC32::digest(CRC32Parameters::BZIP2, CHECK), 0xFC89_1918);
    assert_eq!(CRC32C::digest(CHECK), 0xE306_9283);
}

#[test]
fn adler32_matches_rfc_1950() {
    assert_eq!(Adler32::digest(b""), 0x0000_0001);
    assert_eq!(Adler32::digest(b"a"), 0x0062_0062);
    assert_eq!(Adler32::digest(b"abc"), 0x024D_0127);
    assert_eq!(Adler32::digest(b"Wikipedia"), 0x11E6_0398);
    assert_eq!(Adler32::digest(CHECK), 0x091E_01DE);
}

#[test]
fn streaming_matches_the_one_shot_call() {
    let data: [u8; 8192] = core::array::from_fn(|index| (index * 31 + 7) as u8);
    for split in [0, 1, 63, 64, 5551, 5552, 5553, 8192] {
        let mut crc = CRC32::new(CRC32Parameters::IEEE);
        crc.update(&data[..split]);
        crc.update(&data[split..]);
        assert_eq!(crc.finalize(), CRC32::digest(CRC32Parameters::IEEE, &data));

        let mut adler = Adler32::new();
        adler.update(&data[..split]);
        adler.update(&data[split..]);
        assert_eq!(adler.finalize(), Adler32::digest(&data));

        let mut crc32c = CRC32C::new();
        crc32c.update(&data[..split]);
        crc32c.update(&data[split..]);
        assert_eq!(crc32c.finalize(), CRC32C::digest(&data));
    }
}

#[test]
fn reset_restores_the_initial_state() {
    let mut crc = CRC32::new(CRC32Parameters::IEEE);
    crc.update(b"discarded");
    crc.reset();
    crc.update(CHECK);
    assert_eq!(crc.finalize(), 0xCBF4_3926);

    let mut adler = Adler32::new();
    adler.update(b"discarded");
    adler.reset();
    adler.update(CHECK);
    assert_eq!(adler.finalize(), 0x091E_01DE);
}

#[test]
fn clone_keeps_the_running_state() {
    let mut crc = CRC32::new(CRC32Parameters::IEEE);
    crc.update(b"12345");
    let mut clone = crc.clone();
    crc.update(b"6789");
    clone.update(b"6789");
    assert_eq!(crc.finalize(), clone.finalize());
}
