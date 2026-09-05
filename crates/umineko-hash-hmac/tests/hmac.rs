use umineko_hash_hmac::{Digest, HMACError, HMACFunction, HMAC};
use umineko_hash_md::{MD2, MD4, MD5};
use umineko_hash_ripemd::{RIPEMD160};
use umineko_hash_sha::{SHA0, SHA1, SHA2_224, SHA2_256, SHA2_384, SHA2_512, SHA2_512_224, SHA2_512_256, SHA3_224, SHA3_256, SHA3_384, SHA3_512};
use umineko_hash_sm3::{SM3};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap()).collect()
}

fn text(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn compute<D: Digest>(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut tag = vec![0; D::DIGEST_SIZE];
    assert_eq!(HMAC::<D>::tag(key, data, &mut tag), D::DIGEST_SIZE, "{}", D::NAME);
    tag
}

/// The construction as RFC 2104 section 2 states it, over the hash alone.
fn nested<D: Digest>(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut block = match key.len() > D::BLOCK_SIZE {
        true => {
            let mut hash = D::builtin();
            hash.update(key);
            hash.finalize().as_ref().to_vec()
        }
        false => key.to_vec(),
    };
    block.resize(D::BLOCK_SIZE, 0);
    let mut inner = D::builtin();
    inner.update(&block.iter().map(|byte| byte ^ 0x36).collect::<Vec<u8>>());
    inner.update(data);
    let mut outer = D::builtin();
    outer.update(&block.iter().map(|byte| byte ^ 0x5c).collect::<Vec<u8>>());
    outer.update(inner.finalize().as_ref());
    outer.finalize().as_ref().to_vec()
}

fn compare<D: Digest>(cases: &[(Vec<u8>, Vec<u8>)], expected: &[&str]) {
    for (index, ((key, data), expected)) in cases.iter().zip(expected).enumerate() {
        assert_eq!(text(&compute::<D>(key, data)), *expected, "{} case {}", D::NAME, index + 1);
    }
}

/// The seven cases of RFC 4231 section 4.
fn rfc4231() -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), b"Hi There".to_vec()),
        (b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec()),
        (hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), hex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")),
        (hex("0102030405060708090a0b0c0d0e0f10111213141516171819"), hex("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")),
        (hex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"), b"Test With Truncation".to_vec()),
        (hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec()),
        (hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec()),
    ]
}

/// The seven cases of RFC 2202 section 2, whose keys are as long as the MD5 digest.
fn rfc2202_md5() -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), b"Hi There".to_vec()),
        (b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec()),
        (hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), hex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")),
        (hex("0102030405060708090a0b0c0d0e0f10111213141516171819"), hex("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")),
        (hex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"), b"Test With Truncation".to_vec()),
        (hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec()),
        (hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".to_vec()),
    ]
}

/// The seven cases of RFC 2202 section 3, which RFC 2286 repeats for RIPEMD-160.
fn rfc2202_sha1() -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), b"Hi There".to_vec()),
        (b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec()),
        (hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), hex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")),
        (hex("0102030405060708090a0b0c0d0e0f10111213141516171819"), hex("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")),
        (hex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"), b"Test With Truncation".to_vec()),
        (hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec()),
        (hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".to_vec()),
    ]
}

/// The cases of RFC 4231 that no truncation applies to, and two more whose key is longer than the widest block keyed here.
fn unpublished() -> Vec<(Vec<u8>, Vec<u8>)> {
    vec![
        (hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"), b"Hi There".to_vec()),
        (b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec()),
        (hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), hex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")),
        (hex("0102030405060708090a0b0c0d0e0f10111213141516171819"), hex("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")),
        (hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec()),
        (hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec()),
        (hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec()),
        (hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec()),
    ]
}

#[test]
fn md5_matches_rfc_2202() {
    compare::<MD5>(&rfc2202_md5(), &[
        "9294727a3638bb1c13f48ef8158bfc9d",
        "750c783e6ab0b503eaa86e310a5db738",
        "56be34521d144c88dbb8c733f0e8b3f6",
        "697eaf0aca3a3aea3a75164746ffaa79",
        "56461ef2342edc00f9bab995690efd4c",
        "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd",
        "6f630fad67cda0ee1fb1f562db3aa53e",
    ]);
}

#[test]
fn sha1_matches_rfc_2202() {
    compare::<SHA1>(&rfc2202_sha1(), &[
        "b617318655057264e28bc0b6fb378c8ef146be00",
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
        "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
        "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
        "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
        "aa4ae5e15272d00e95705637ce8a3b55ed402112",
        "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
    ]);
}

#[test]
fn ripemd160_matches_rfc_2286() {
    compare::<RIPEMD160>(&rfc2202_sha1(), &[
        "24cb4bd67d20fc1a5d2ed7732dcc39377f0a5668",
        "dda6c0213a485a9e24f4742064a7f033b43c4069",
        "b0b105360de759960ab4f35298e116e295d8e7c1",
        "d5ca862f4d21d5e610e18b4cf1beb97a4365ecf4",
        "7619693978f91d90539ae786500ff3d8e0518e39",
        "6466ca07ac5eac29e1bd523e5ada7605b791fd8b",
        "69ea60798d71616cce5fd0871e23754cd75d5a0a",
    ]);
}

#[test]
fn sha2_224_matches_rfc_4231() {
    compare::<SHA2_224>(&rfc4231(), &[
        "896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22",
        "a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44",
        "7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea",
        "6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a",
        "0e2aea68a90c8d37c988bcdb9fca6fa8099cd857c7ec4a1815cac54c",
        "95e9a0db962095adaebe9b2d6f0dbce2d499f112f2d2b7273fa6870e",
        "3a854166ac5d9f023f54d517d0b39dbd946770db9c2b95c9f6f565d1",
    ]);
}

#[test]
fn sha2_256_matches_rfc_4231() {
    compare::<SHA2_256>(&rfc4231(), &[
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
        "a3b6167473100ee06e0c796c2955552bfa6f7c0a6a8aef8b93f860aab0cd20c5",
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
    ]);
}

#[test]
fn sha2_384_matches_rfc_4231() {
    compare::<SHA2_384>(&rfc4231(), &[
        "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6",
        "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649",
        "88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27",
        "3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb",
        "3abf34c3503b2a23a46efc619baef897f4c8e42c934ce55ccbae9740fcbc1af4ca62269e2a37cd88ba926341efe4aeea",
        "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952",
        "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5a678cc31e799176d3860e6110c46523e",
    ]);
}

#[test]
fn sha2_512_matches_rfc_4231() {
    compare::<SHA2_512>(&rfc4231(), &[
        "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
        "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
        "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
        "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd",
        "415fad6271580a531d4179bc891d87a650188707922a4fbb36663a1eb16da008711c5b50ddd0fc235084eb9d3364a1454fb2ef67cd1d29fe6773068ea266e96b",
        "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
        "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
    ]);
}

#[test]
fn sha2_512_224_matches_the_reference() {
    compare::<SHA2_512_224>(&unpublished(), &[
        "b244ba01307c0e7a8ccaad13b1067a4cf6b961fe0c6a20bda3d92039",
        "4a530b31a79ebcce36916546317c45f247d83241dfb818fd37254bde",
        "db34ea525c2c216ee5a6ccb6608bea870bbef12fd9b96a5109e2b6fc",
        "c2391863cda465c6828af06ac5d4b72d0b792109952da530e11a0d26",
        "29bef8ce88b54d4226c3c7718ea9e32ace2429026f089e38cea9aeda",
        "82a9619b47af0cea73a8b9741355ce902d807ad87ee9078522a246e1",
        "01c34e40d6739bb74f3bc75e6626cafcf7772c4ab97221ce5c63ec30",
        "86f2053d99268fb0be063fae7dea3ee795dc7b0cd8aa426939fc5bf3",
    ]);
}

#[test]
fn sha2_512_256_matches_the_reference() {
    compare::<SHA2_512_256>(&unpublished(), &[
        "9f9126c3d9c3c330d760425ca8a217e31feae31bfe70196ff81642b868402eab",
        "6df7b24630d5ccb2ee335407081a87188c221489768fa2020513b2d593359456",
        "229006391d66c8ecddf43ba5cf8f83530ef221a4e9401840d1bead5137c8a2ea",
        "36d60c8aa1d0be856e10804cf836e821e8733cbafeae87630589fd0b9b0a2f4c",
        "87123c45f7c537a404f8f47cdbedda1fc9bec60eeb971982ce7ef10e774e6539",
        "6ea83f8e7315072c0bdaa33b93a26fc1659974637a9db8a887d06c05a7f35a66",
        "0957199dfbc37da09ec17f76b13b6e6480d5c971e6926f06260dfad0100fda3a",
        "a0fa58f27b725f00b75374b85d68b453bc392a1c562bafe241f88455168f35c6",
    ]);
}

#[test]
fn sha3_224_matches_the_reference() {
    compare::<SHA3_224>(&unpublished(), &[
        "3b16546bbc7be2706a031dcafd56373d9884367641d8c59af3c860f7",
        "7fdb8dd88bd2f60d1b798634ad386811c2cfc85bfaf5d52bbace5e66",
        "676cfc7d16153638780390692be142d2df7ce924b909c0c08dbfdc1a",
        "a9d7685a19c4e0dbd9df2556cc8a7d2a7733b67625ce594c78270eeb",
        "b4a1f04c00287a9b7f6075b313d279b833bc8f75124352d05fb9995f",
        "05d8cd6d00faea8d1eb68ade28730bbd3cbab6929f0a086b29cd62a0",
        "5e73d57bd011f0f92fef3c3b92ea4bcb4821c6d83c37db34f29e0760",
        "a2ca69565a820a0461d1bd4c7d77c88a9446bd672d5ef91b4bdea59e",
    ]);
}

#[test]
fn sha3_256_matches_the_reference() {
    compare::<SHA3_256>(&unpublished(), &[
        "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb",
        "c7d4072e788877ae3596bbb0da73b887c9171f93095b294ae857fbe2645e1ba5",
        "84ec79124a27107865cedd8bd82da9965e5ed8c37b0ac98005a7f39ed58a4207",
        "57366a45e2305321a4bc5aa5fe2ef8a921f6af8273d7fe7be6cfedb3f0aea6d7",
        "ed73a374b96c005235f948032f09674a58c0ce555cfc1f223b02356560312c3b",
        "65c5b06d4c3de32a7aef8763261e49adb6e2293ec8e7c61e8de61701fc63e123",
        "49ad92b02124fdac9627ae45e008a696182ab6bfb8470457777c744aeb9df06f",
        "3dc57f3eae92353f48bc49e7a30412071f5679590a62abeda8c0a83511b46b14",
    ]);
}

#[test]
fn sha3_384_matches_the_reference() {
    compare::<SHA3_384>(&unpublished(), &[
        "68d2dcf7fd4ddd0a2240c8a437305f61fb7334cfb5d0226e1bc27dc10a2e723a20d370b47743130e26ac7e3d532886bd",
        "f1101f8cbf9766fd6764d2ed61903f21ca9b18f57cf3e1a23ca13508a93243ce48c045dc007f26a21b3f5e0e9df4c20a",
        "275cd0e661bb8b151c64d288f1f782fb91a8abd56858d72babb2d476f0458373b41b6ab5bf174bec422e53fc3135ac6e",
        "3a5d7a879702c086bc96d1dd8aa15d9c46446b95521311c606fdc4e308f4b984da2d0f9449b3ba8425ec7fb8c31bc136",
        "0fc19513bf6bd878037016706a0e57bc528139836b9a42c3d419e498e0e1fb9616fd669138d33a1105e07c72b6953bcc",
        "026fdf6b50741e373899c9f7d5406d4eb09fc6665636fc1a530029ddf5cf3ca5a900edce01f5f61e2f408cdf2fd3e7e8",
        "3e7b62d091d75f484892bc2ed26d7b0ed37c9529f0227197cc8522971eb6f7215dd4e0cc6ea306987e0cbfe914f3a916",
        "695695feae1ddb879ec5ba0337dbd6ff543208ef112568ab3872208e635ecf46c99e7859935534680a8d833eef7af4b4",
    ]);
}

#[test]
fn sha3_512_matches_the_reference() {
    compare::<SHA3_512>(&unpublished(), &[
        "eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e",
        "5a4bfeab6166427c7a3647b747292b8384537cdb89afb3bf5665e4c5e709350b287baec921fd7ca0ee7a0c31d022a95e1fc92ba9d77df883960275beb4e62024",
        "309e99f9ec075ec6c6d475eda1180687fcf1531195802a99b5677449a8625182851cb332afb6a89c411325fbcbcd42afcb7b6e5aab7ea42c660f97fd8584bf03",
        "b27eab1d6e8d87461c29f7f5739dd58e98aa35f8e823ad38c5492a2088fa0281993bbfff9a0e9c6bf121ae9ec9bb09d84a5ebac817182ea974673fb133ca0d1d",
        "00f751a9e50695b090ed6911a4b65524951cdc15a73a5d58bb55215ea2cd839ac79d2b44a39bafab27e83fde9e11f6340b11d991b1b91bf2eee7fc872426c3a4",
        "38a456a004bd10d32c9ab8336684112862c3db61adcca31829355eaf46fd5c73d06a1f0d13fec9a652fb3811b577b1b1d1b9789f97ae5b83c6f44dfcf1d67eba",
        "fafc7b7fe3332ce153966b27f6586fa5b49ec5d8dff3d7fd26a011451ca4c9de437913879159d9c5181a9a6f377ef18b48399756decea695b04fe90a9d3b93d1",
        "ecb0b14ffb6632f779c1d15a79c41302e14e0c11d6794e08c0276721e89bdec0956a29c934ada2ba9a877861f3505b9f24a5b8d599c8c370e3fb2f1504248c6f",
    ]);
}

#[test]
fn sm3_matches_the_reference() {
    compare::<SM3>(&unpublished(), &[
        "51b00d1fb49832bfb01c3ce27848e59f871d9ba938dc563b338ca964755cce70",
        "2e87f1d16862e6d964b50a5200bf2b10b764faa9680a296a2405f24bec39f882",
        "dd9421e1c725bdf52ec1aa34edadb3c97f5951a83a2fa93f73a7902bc1dcc777",
        "b57c79be03472aeb8cada581dea332cb2ba83d19cb1b052dd07194def75fb8cd",
        "b4fd844e13342002f0b2e0690ea7741f1497d993a70494cea601e657bedf67a0",
        "5acbdeb0c8c1ef3a99088fe51c0a1d5f4e1c175935f016aee74eb8056db18acb",
        "7fe81376928b28f18a41cc533a8d654ef78345ecd7b3807c0913545b77abe6e3",
        "b90a2e0860e190447d4dec929815ab424ef89edc7b5577eab04d5991d9888228",
    ]);
}

#[test]
fn sha2_truncates_to_the_leading_bytes_of_the_tag() {
    let (key, data) = rfc4231()[4].clone();
    let mut tag = [0; 16];
    assert_eq!(HMAC::<SHA2_224>::tag(&key, &data, &mut tag), 16);
    assert_eq!(text(&tag), "0e2aea68a90c8d37c988bcdb9fca6fa8");
    assert_eq!(HMAC::<SHA2_256>::tag(&key, &data, &mut tag), 16);
    assert_eq!(text(&tag), "a3b6167473100ee06e0c796c2955552b");
    assert_eq!(HMAC::<SHA2_384>::tag(&key, &data, &mut tag), 16);
    assert_eq!(text(&tag), "3abf34c3503b2a23a46efc619baef897");
    assert_eq!(HMAC::<SHA2_512>::tag(&key, &data, &mut tag), 16);
    assert_eq!(text(&tag), "415fad6271580a531d4179bc891d87a6");
}

/// Every key length either side of a block, over the definition of RFC 2104 section 2.
fn definition<D: Digest>() {
    let data: Vec<u8> = (0..250).map(|index| (index * 7 + 1) as u8).collect();
    for length in [0, 1, D::DIGEST_SIZE, D::BLOCK_SIZE - 1, D::BLOCK_SIZE, D::BLOCK_SIZE + 1, D::BLOCK_SIZE * 3] {
        let key: Vec<u8> = (0..length).map(|index| (index * 3 + 5) as u8).collect();
        for split in [0, 1, data.len()] {
            assert_eq!(text(&compute::<D>(&key, &data[..split])), text(&nested::<D>(&key, &data[..split])), "{} with a key of {length} and a message of {split}", D::NAME);
        }
    }
}

#[test]
fn matches_the_definition() {
    definition::<MD2>();
    definition::<MD4>();
    definition::<MD5>();
    definition::<RIPEMD160>();
    definition::<SHA0>();
    definition::<SHA1>();
    definition::<SHA2_224>();
    definition::<SHA2_256>();
    definition::<SHA2_384>();
    definition::<SHA2_512>();
    definition::<SHA2_512_224>();
    definition::<SHA2_512_256>();
    definition::<SHA3_224>();
    definition::<SHA3_256>();
    definition::<SHA3_384>();
    definition::<SHA3_512>();
    definition::<SM3>();
}

/// RFC 2104 section 2 pads a key shorter than a block with zeroes, so both keys are the same key.
#[test]
fn pads_a_short_key_with_zeroes() {
    let data = b"padding";
    let key = hex("0102030405");
    let mut padded = key.clone();
    padded.resize(SHA2_256::BLOCK_SIZE, 0);
    assert_eq!(text(&compute::<SHA2_256>(&key, data)), text(&compute::<SHA2_256>(&padded, data)));
    let mut padded = key.clone();
    padded.resize(SHA3_512::BLOCK_SIZE, 0);
    assert_eq!(text(&compute::<SHA3_512>(&key, data)), text(&compute::<SHA3_512>(&padded, data)));
}

/// RFC 2104 section 2 hashes a key longer than a block first, so both keys are the same key.
#[test]
fn hashes_a_long_key_first() {
    let data = b"shortening";
    let key: Vec<u8> = (0..200).map(|index| (index * 5 + 9) as u8).collect();
    assert_eq!(text(&compute::<SHA2_256>(&key, data)), text(&compute::<SHA2_256>(&SHA2_256::digest(&key), data)));
    assert_eq!(text(&compute::<SM3>(&key, data)), text(&compute::<SM3>(&SM3::digest(&key), data)));
    assert_eq!(text(&compute::<SHA3_384>(&key, data)), text(&compute::<SHA3_384>(&SHA3_384::digest(&key), data)));
}

#[test]
fn streaming_matches_the_one_shot_call() {
    let key = hex("6b6579");
    let data: Vec<u8> = (0..1000).map(|index| (index * 11 + 3) as u8).collect();
    for split in [0, 1, 63, 64, 65, 135, 136, 999, 1000] {
        let mut mac = HMAC::<SHA2_256>::new(&key);
        mac.update(&data[..split]);
        mac.update(&data[split..]);
        let mut tag = [0; 32];
        mac.finalize(&mut tag);
        assert_eq!(text(&tag), text(&compute::<SHA2_256>(&key, &data)), "at {split}");
    }
}

#[test]
fn reset_returns_to_the_keyed_state() {
    let key = hex("0b0b0b0b");
    let mut mac = HMAC::<SHA2_256>::new(&key);
    mac.update(b"discarded");
    mac.reset();
    mac.update(b"Hi There");
    let mut tag = [0; 32];
    mac.finalize(&mut tag);
    assert_eq!(text(&tag), text(&compute::<SHA2_256>(&key, b"Hi There")));
}

#[test]
fn a_clone_carries_on_alone() {
    let key = hex("0b0b0b0b");
    let mut mac = HMAC::<SHA2_256>::new(&key);
    mac.update(b"Hi ");
    let mut clone = mac.clone();
    clone.update(b"There");
    mac.update(b"You");
    let (mut first, mut second) = ([0; 32], [0; 32]);
    clone.finalize(&mut first);
    mac.finalize(&mut second);
    assert_eq!(text(&first), text(&compute::<SHA2_256>(&key, b"Hi There")));
    assert_eq!(text(&second), text(&compute::<SHA2_256>(&key, b"Hi You")));
}

#[test]
fn verify_accepts_the_tag_and_refuses_a_changed_one() {
    let (key, data) = (hex("4a656665"), b"what do ya want for nothing?");
    let expected = compute::<SHA2_256>(&key, data);
    assert_eq!(HMAC::<SHA2_256>::authenticate(&key, data, &expected), Ok(()));
    for index in [0, 15, 31] {
        let mut changed = expected.clone();
        changed[index] ^= 1;
        assert_eq!(HMAC::<SHA2_256>::authenticate(&key, data, &changed), Err(HMACError::Authentication));
    }
    assert_eq!(HMAC::<SHA2_256>::authenticate(&hex("4a656665ff"), data, &expected), Err(HMACError::Authentication));
    assert_eq!(HMAC::<SHA2_256>::authenticate(&key, b"what do ya want for nothing", &expected), Err(HMACError::Authentication));
}

#[test]
fn verify_accepts_a_truncated_tag_and_refuses_a_length_no_tag_has() {
    let (key, data) = (hex("4a656665"), b"Hi There");
    let expected = compute::<SHA2_256>(&key, data);
    assert_eq!(HMAC::<SHA2_256>::authenticate(&key, data, &expected[..16]), Ok(()));
    assert_eq!(HMAC::<SHA2_256>::authenticate(&key, data, &expected[..1]), Ok(()));
    let mut changed = expected.clone();
    changed[3] ^= 1;
    assert_eq!(HMAC::<SHA2_256>::authenticate(&key, data, &changed[..16]), Err(HMACError::Authentication));
    assert_eq!(HMAC::<SHA2_256>::authenticate(&key, data, &[]), Err(HMACError::Length));
    let mut longer = expected.clone();
    longer.push(0);
    assert_eq!(HMAC::<SHA2_256>::authenticate(&key, data, &longer), Err(HMACError::Length));
}

#[test]
fn finalize_reports_what_it_wrote() {
    let key = hex("0b0b0b0b");
    let expected = compute::<SHA2_256>(&key, b"Hi There");
    for length in [1, 16, 31, 32] {
        let mut mac = HMAC::<SHA2_256>::new(&key);
        mac.update(b"Hi There");
        let mut tag = vec![0xff; length];
        assert_eq!(mac.finalize(&mut tag), length);
        assert_eq!(text(&tag), text(&expected[..length]));
    }
    let mut mac = HMAC::<SHA2_256>::new(&key);
    mac.update(b"Hi There");
    let mut tag = vec![0xff; 40];
    assert_eq!(mac.finalize(&mut tag), 32);
    assert_eq!(text(&tag[..32]), text(&expected));
    assert_eq!(text(&tag[32..]), "ff".repeat(8));
}

#[test]
fn the_two_builders_agree() {
    let key = hex("0102030405");
    let mut first = HMAC::<SHA2_256>::new(&key);
    let mut second = HMAC::<SHA2_256>::builtin(&key);
    first.update(b"Hi There");
    second.update(b"Hi There");
    let (mut left, mut right) = ([0; 32], [0; 32]);
    first.finalize(&mut left);
    second.finalize(&mut right);
    assert_eq!(text(&left), text(&right));
    assert_eq!(HMAC::<SHA2_256>::digest_size(), 32);
    assert_eq!(HMAC::<SHA2_256>::block_size(), 64);
    assert_eq!(HMAC::<SHA3_224>::block_size(), 144);
}

#[test]
fn the_keyless_function_computes_what_the_keyed_hash_does() {
    let function = HMACFunction::<SHA2_256>::new();
    assert_eq!(function.name(), "HMAC");
    assert_eq!(function.digest(), "SHA-256");
    assert_eq!(function.output_size(), 32);
    assert_eq!(function.block_size(), 64);
    assert_eq!(function, HMACFunction::<SHA2_256>::default());
    for (key, data) in rfc4231() {
        let mut output = vec![0; function.output_size()];
        assert_eq!(function.compute(&key, &data, &mut output), 32);
        assert_eq!(text(&output), text(&compute::<SHA2_256>(&key, &data)));
    }
    let sha1 = HMACFunction::<SHA1>::new();
    assert_eq!((sha1.digest(), sha1.output_size(), sha1.block_size()), ("SHA-1", 20, 64));
    let sha3 = HMACFunction::<SHA3_512>::new();
    assert_eq!((sha3.digest(), sha3.output_size(), sha3.block_size()), ("SHA3-512", 64, 72));
}
