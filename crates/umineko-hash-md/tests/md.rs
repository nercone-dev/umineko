use umineko_hash_md::{MD2, MD4, MD5};

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

const SUITE: [&str; 7] = ["", "a", "abc", "message digest", "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "12345678901234567890123456789012345678901234567890123456789012345678901234567890"];

#[test]
fn md2_matches_rfc_1319() {
    let digests = [
        "8350e5a3e24c153df2275c9f80692773",
        "32ec01ec4a6dac72c0ab96fb34c0b5d1",
        "da853b0d3f88d99b30283a69e6ded6bb",
        "ab4f496bfb2a530b219ff33031fe06b0",
        "4e8ddff3650292ab5a4108c3aa47940b",
        "da33def2a42df13975352846c30338cd",
        "d5976f79d83d3a0dc9806c3c66f3efd8",
    ];
    for (data, digest) in SUITE.iter().zip(digests) {
        assert_eq!(hex(&MD2::digest(data.as_bytes())), digest, "{data}");
    }
}

#[test]
fn md4_matches_rfc_1320() {
    let digests = [
        "31d6cfe0d16ae931b73c59d7e0c089c0",
        "bde52cb31de33e46245e05fbdbd6fb24",
        "a448017aaf21d8525fc10ae87aa6729d",
        "d9130a8164549fe818874806e1c7014b",
        "d79e1c308aa5bbcdeea8ed63df412da9",
        "043f8582f241db351ce627e153e7f0e4",
        "e33b4ddc9c38f2199c3e7b164fcc0536",
    ];
    for (data, digest) in SUITE.iter().zip(digests) {
        assert_eq!(hex(&MD4::digest(data.as_bytes())), digest, "{data}");
    }
}

#[test]
fn md5_matches_rfc_1321() {
    let digests = [
        "d41d8cd98f00b204e9800998ecf8427e",
        "0cc175b9c0f1b6a831c399e269772661",
        "900150983cd24fb0d6963f7d28e17f72",
        "f96b697d7cb7938d525a2f31aaf161d0",
        "c3fcd3d76192e4007dfb496cca67e13b",
        "d174ab98d277d9f5a5611c2c9f419d9f",
        "57edf4a22be3c955ac49da2e2107b67a",
    ];
    for (data, digest) in SUITE.iter().zip(digests) {
        assert_eq!(hex(&MD5::digest(data.as_bytes())), digest, "{data}");
    }
}

#[test]
fn streaming_matches_the_one_shot_call() {
    let data: [u8; 1000] = core::array::from_fn(|index| (index * 17 + 3) as u8);
    for split in [0, 1, 15, 16, 17, 63, 64, 65, 128, 999, 1000] {
        let mut md2 = MD2::new();
        md2.update(&data[..split]);
        md2.update(&data[split..]);
        assert_eq!(md2.finalize(), MD2::digest(&data), "MD2 at {split}");

        let mut md4 = MD4::new();
        md4.update(&data[..split]);
        md4.update(&data[split..]);
        assert_eq!(md4.finalize(), MD4::digest(&data), "MD4 at {split}");

        let mut md5 = MD5::new();
        md5.update(&data[..split]);
        md5.update(&data[split..]);
        assert_eq!(md5.finalize(), MD5::digest(&data), "MD5 at {split}");
    }
}

#[test]
fn reset_restores_the_initial_state() {
    let mut md5 = MD5::new();
    md5.update(b"discarded");
    md5.reset();
    md5.update(b"abc");
    assert_eq!(hex(&md5.finalize()), "900150983cd24fb0d6963f7d28e17f72");
}
