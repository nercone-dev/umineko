use umineko_hash_ripemd::RIPEMD160;

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn ripemd160_matches_the_reference_vectors() {
    let suite = [
        ("", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        ("a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
        ("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        ("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36"),
        ("abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"),
        ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "12a053384a9c0c88e405a06c27dcf49ada62eb2b"),
        ("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "b0e20b6e3116640286ed3a87a5713079b21f5189"),
        ("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "9b752e45573d4b39f4dbd3323cab82bf63326bfb"),
    ];
    for (data, digest) in suite {
        assert_eq!(hex(&RIPEMD160::digest(data.as_bytes())), digest, "{data}");
    }
}

#[test]
fn ripemd160_streams_a_million_letters() {
    let mut hash = RIPEMD160::new();
    for _ in 0..1000 {
        hash.update(&[b'a'; 1000]);
    }
    assert_eq!(hex(&hash.finalize()), "52783243c1697bdbe16d37f97f68f08325dc1528");
}

#[test]
fn streaming_matches_the_one_shot_call() {
    let data: [u8; 1000] = core::array::from_fn(|index| (index * 7 + 1) as u8);
    for split in [0, 1, 63, 64, 65, 999, 1000] {
        let mut hash = RIPEMD160::new();
        hash.update(&data[..split]);
        hash.update(&data[split..]);
        assert_eq!(hash.finalize(), RIPEMD160::digest(&data), "at {split}");
    }
}
