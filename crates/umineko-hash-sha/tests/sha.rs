use umineko_hash_sha::{SHA0, SHA1, SHA2_224, SHA2_256, SHA2_384, SHA2_512, SHA2_512_224, SHA2_512_256, SHA3_224, SHA3_256, SHA3_384, SHA3_512, SHAKE128, SHAKE256};

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

const ABC: &[u8] = b"abc";
const LONG: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
const LONGER: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

#[test]
fn sha0_matches_fips_180() {
    assert_eq!(hex(&SHA0::digest(ABC)), "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880");
    assert_eq!(hex(&SHA0::digest(LONG)), "d2516ee1acfa5baf33dfc1c471e438449ef134c8");
}

#[test]
fn sha1_matches_fips_180_1() {
    assert_eq!(hex(&SHA1::digest(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(hex(&SHA1::digest(ABC)), "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(hex(&SHA1::digest(LONG)), "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
}

#[test]
fn sha2_matches_fips_180_4() {
    assert_eq!(hex(&SHA2_224::digest(ABC)), "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
    assert_eq!(hex(&SHA2_224::digest(LONG)), "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525");
    assert_eq!(hex(&SHA2_256::digest(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq!(hex(&SHA2_256::digest(ABC)), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq!(hex(&SHA2_256::digest(LONG)), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    assert_eq!(hex(&SHA2_384::digest(ABC)), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
    assert_eq!(hex(&SHA2_384::digest(LONGER)), "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039");
    assert_eq!(hex(&SHA2_512::digest(ABC)), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    assert_eq!(hex(&SHA2_512::digest(LONGER)), "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909");
    assert_eq!(hex(&SHA2_512_224::digest(ABC)), "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");
    assert_eq!(hex(&SHA2_512_224::digest(LONGER)), "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9");
    assert_eq!(hex(&SHA2_512_256::digest(ABC)), "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");
    assert_eq!(hex(&SHA2_512_256::digest(LONGER)), "3928e184fb8690f840da3988121d31be65cb9d3ef83ee6146feac861e19b563a");
}

#[test]
fn sha3_matches_fips_202() {
    assert_eq!(hex(&SHA3_224::digest(b"")), "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
    assert_eq!(hex(&SHA3_224::digest(ABC)), "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
    assert_eq!(hex(&SHA3_256::digest(b"")), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    assert_eq!(hex(&SHA3_256::digest(ABC)), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    assert_eq!(hex(&SHA3_384::digest(b"")), "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
    assert_eq!(hex(&SHA3_384::digest(ABC)), "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25");
    assert_eq!(hex(&SHA3_512::digest(b"")), "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
    assert_eq!(hex(&SHA3_512::digest(ABC)), "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
}

#[test]
fn shake_matches_fips_202() {
    let mut digest = [0; 32];
    SHAKE128::digest(b"", &mut digest);
    assert_eq!(hex(&digest), "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    SHAKE128::digest(ABC, &mut digest);
    assert_eq!(hex(&digest), "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8");
    let mut digest = [0; 64];
    SHAKE256::digest(b"", &mut digest);
    assert_eq!(hex(&digest), "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be");
    SHAKE256::digest(ABC, &mut digest);
    assert_eq!(hex(&digest), "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4");
}

#[test]
fn shake_output_is_a_prefix_of_a_longer_one() {
    let mut short = [0; 16];
    let mut long = [0; 512];
    SHAKE128::digest(ABC, &mut short);
    SHAKE128::digest(ABC, &mut long);
    assert_eq!(short, long[..16]);
}

#[test]
fn streaming_matches_the_one_shot_call() {
    let data: [u8; 4096] = core::array::from_fn(|index| (index * 13 + 5) as u8);
    for split in [0, 1, 63, 64, 71, 72, 103, 104, 127, 128, 135, 136, 143, 144, 167, 168, 4095, 4096] {
        let mut sha1 = SHA1::new();
        sha1.update(&data[..split]);
        sha1.update(&data[split..]);
        assert_eq!(sha1.finalize(), SHA1::digest(&data), "SHA-1 at {split}");

        let mut sha256 = SHA2_256::new();
        sha256.update(&data[..split]);
        sha256.update(&data[split..]);
        assert_eq!(sha256.finalize(), SHA2_256::digest(&data), "SHA-256 at {split}");

        let mut sha512 = SHA2_512::new();
        sha512.update(&data[..split]);
        sha512.update(&data[split..]);
        assert_eq!(sha512.finalize(), SHA2_512::digest(&data), "SHA-512 at {split}");

        let mut sha3 = SHA3_256::new();
        sha3.update(&data[..split]);
        sha3.update(&data[split..]);
        assert_eq!(sha3.finalize(), SHA3_256::digest(&data), "SHA3-256 at {split}");

        let mut shake = SHAKE128::new();
        let mut streamed = [0; 40];
        let mut once = [0; 40];
        shake.update(&data[..split]);
        shake.update(&data[split..]);
        shake.finalize(&mut streamed);
        SHAKE128::digest(&data, &mut once);
        assert_eq!(streamed, once, "SHAKE128 at {split}");
    }
}

#[test]
fn reset_restores_the_initial_state() {
    let mut sha256 = SHA2_256::new();
    sha256.update(b"discarded");
    sha256.reset();
    sha256.update(ABC);
    assert_eq!(hex(&sha256.finalize()), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    let mut sha3 = SHA3_512::new();
    sha3.update(b"discarded");
    sha3.reset();
    sha3.update(ABC);
    assert_eq!(hex(&sha3.finalize()), "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
}
