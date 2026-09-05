use umineko_hash_sm3::SM3;

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn sm3_matches_gb_t_32905() {
    assert_eq!(hex(&SM3::digest(b"abc")), "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
    let long = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    assert_eq!(hex(&SM3::digest(long)), "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732");
}

#[test]
fn streaming_matches_the_one_shot_call() {
    let data: [u8; 1000] = core::array::from_fn(|index| (index * 11 + 3) as u8);
    for split in [0, 1, 63, 64, 65, 999, 1000] {
        let mut hash = SM3::new();
        hash.update(&data[..split]);
        hash.update(&data[split..]);
        assert_eq!(hash.finalize(), SM3::digest(&data), "at {split}");
    }
}
