use umineko_hash_md::MD6;

fn data(length: usize) -> Vec<u8> {
    (0..length).map(|index| (index * 7 + 11) as u8).collect()
}

fn hex(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

const LENGTHS: [usize; 16] = [0, 1, 3, 34, 100, 511, 512, 513, 1024, 2047, 2048, 2049, 4096, 8192, 8193, 10000];

const MD6_256: [&str; 16] = [
    "bca38b24a804aa37d821d31af00f5598230122c5bbfc4c4ad5ed40e4258f04ca",
    "bb97a9ac31997c3691dac3115420c9eeb55dfdab5f67dbd427c4d8fce39e757f",
    "a153d5f0ca11d22c74922c58cc0b8c5c6c92c6b5922b351883ddaefe2e28ba0a",
    "a739e777c2a9945e881553c23ebfa81a5bd2b6e574877ab6ee41d7c05a2668f9",
    "3669139034f23756ebc59c12871da2960c58210d795ad5339e0b34d302071dbb",
    "c30e3029c584f4ef6c12de6608df4e4c9db63bb99e0c1a673aebe801193e59d7",
    "0153f3da94721e8dc36e849a4c192a8efba746d0e2e7508499084f7d1e42d04e",
    "29ce73ed60c1a0e504da9711e6a5717728fb1692017a2f9131847c158145e8c0",
    "3db96f77b48f67d603c470527794e122034e2924201ed011b5b22c129b5c7309",
    "8be6d983bff510f56af1db576e781d6a433c98b781eb0def3183feb3a0e2d00c",
    "39afc2ded2a6b199a7c607e8c0b9bdac76c1a33f7899fb7fd5c9831a368471d3",
    "bf2c21bf67adcc0c11a0355f58d00ddbce322c65f1c26dc841bc7b95b5da7a5b",
    "b77217c62a3ecbbd278b2ac128e8d21df8d4b00477053b34bd9c1ce8447e90c6",
    "e3505927c599b29188bb4313243f394a1c318842a2b5d2fa5014e7e1d40613f6",
    "c2d1d338102d91983a748da57601f2323b05eeeb2d620da2ce4446cd1e4e5543",
    "ae0ed7e85e3778d4663e766c1712bcda85c680fe8af119566bc31de46a2beb1e",
];

const MD6_224: [&str; 16] = [
    "d2091aa2ad17f38c51ade2697f24cafc3894c617c77ffe10fdc7abcb",
    "016881ce4d732211be29195f5ab6d76970b9ea6ec49cc639cd291349",
    "f31787ee2423822549e294b21fecac4951eaa223e598cffc61dd1fca",
    "862024637e12248d73b93dfeacded8a5e27e0c9482b0ef809be06f0e",
    "1c1ea4f477833b6ab5a40e326b8f72f3815e52b948c263056264f7d5",
    "140129726382faddfeaf92b91174ba5b97abcc2426735fd7bd87bb27",
    "83b32826eca68d4c29b7fc0a75444e7dec6fb6ed240f789475715361",
    "e27fe93ed3008afce343eba8a8c83c607a14c37c1c699145a553d3cd",
    "5bd503862417e648cde077ecfbd0fc4de1c47c4f86c502d8b73d4e37",
    "86a9c5a5b7acf70f838caa2c2f8905201ce5aef6a9943a6205d2974c",
    "3be91eea8deefbe54cbb9a74dbd7d82b67a0184de717129000ecb7b5",
    "b313a8d8cf51a6729d154be1a016ccee13227ee5663aeb38d33c65f5",
    "5e99f7d703b37ca3f38bbe092cacf6d00b15343f32ebb1398d0ab825",
    "ae816ff7b2fc65f0a6e05054c8a4b2ec761be463ad33e5bfeb04c978",
    "e056b0079cb29765fa2254d0d78dadfb1d46b122072c6dcd2ac4e0e0",
    "c091ef2e91abb9208f1d1cc5cd38e35dc46168437edc9aac5b4102f5",
];

const MD6_512: [&str; 16] = [
    "6b7f33821a2c060ecdd81aefddea2fd3c4720270e18654f4cb08ece49ccb469f8beeee7c831206bd577f9f2630d9177979203a9489e47e04df4e6deaa0f8e0c0",
    "9cfbb223372c31ebc81909d53e45bca16e1eda170a8e1ac5933c39af314ebf41b117242ce4f7fbc051d9ed7d5b35cacb00f6f2a64d925a234f769ad30dcd8358",
    "d2efa86dffd545dfd427b9b24ae472a814770b71134bf790c416ad5321b883f04eafa43a8ba4144c84f57456b7d6b39a080ecada1e5c93bc14fe143494f36ed0",
    "8e9aa183c2aedefb8c06dd29696e83725fd1a559afc047c64f10759ab96e85f4f7697648d1d23a5dfb0f1c20dc8aff408e233459acf53197810fa0f6ffed56e9",
    "5565db140ffd8ced09164a57576636079d0e8a5de6b9ecbef3fce1a36a9fbb99c492dbcc18c3c5d20aa16dfee0ce8b2d09e0c666c2113917ab15157cd490e7c5",
    "12a055b69f239543ac9d8248078fea072ffd05680e82fa55b0df640b5af2f97ed7944845d60a75314c7799f8ae19beac399aad8fd110e48a40af8497554e03fb",
    "87a5cac2c28ea83ca50be48490e969c024a50c4d16a14ae97cfa23c6e246327357795b865e23992974c4753c11e7f7f94f8ded5cef59efec55192b330b7cc861",
    "1c73485070ee0958d38625d4be2b495fd814eda77ec1d02806ef64db58b7a163092f31a0ccfe30b9e2c34d55ab1054e090ea7309133ca56b206298f64730690f",
    "09c965dab6a9541d0c35bc1d8ca9151d14f66934f10577761a4a9d7dcc0febddc3f8a89a2f0122b562d169bdd37e080430dd4f1c6d10ef1ac7e8fe52feb80fb2",
    "d74694fc1df342ef7be7f8768cbc6f33d0560307ca382019742db4a46ba052bee2765b2eef6c593ae9b70bf5d7ff993fa299ecfdde4fab2049ee73fc6bb6ed6e",
    "5553f44539516bfc285cff4b08a2b30ae0a99ba9322222d403e567f740a6e0de1874c1813efe767ba74308ee25797ddbb15a0b8786c41896cb9bbd1b116d05a5",
    "77b500f4107a7a7d8b9552695e0e066969e31cc8c3c39a3b1c420770080185629c804a0de8e86417a5ca9b45b754242158fa8b66af23df249863755fd47c9342",
    "a788937f2c9e2086f5320fa0b651bfd3e471212b3628afc4d6bdc5778d48d9876a3fb4e90ce4b9c4047df7bc0a7354378c0e47c22827d196118280470031fb00",
    "ea4fa512460034a091e0876c8f370d787d6e6c40101535ee729a6bce28143150971f5578d86cf0d304ac0a114549b888d16088e248cb3b5f0d7c60ba17fac202",
    "eb9c56f009e0acb3f1baf8e020c9b2713b9a0fe076d02158abd55215bf29defb72ec49167a819cdf6ff278f0dfd44893323fc4013298e698c4adc7a442141ead",
    "d54a4b0492dea18d6e8efa446bc0757ac59cfa6f536576fca49195a52736da4b9a6e0671a8e97ce845d84c86ee86ce88c04999c97e75676e9084e4a540039526",
];

const MD6_KEYED: [&str; 16] = [
    "f813e9ed00e1d59ac1abf62137a4a40a4016945a879ed195d2a90bde33dde0dc",
    "78c8c9184fc0c6af9991c38af541bbac4cbad215c6510df70839183cbdbe0eac",
    "f50ad94ccdcd4caf3371643d184d61b06ce668f4c236b7c4ede100243ef205ae",
    "7da0499ff1d48a4b7669070c9a96a0ed08a29bbb1a92ef18cb3255569377365b",
    "8d63cb4916f5112dbb856c2a023f1c9bf36c432658f7922ce7574bd7b07c59b3",
    "376e861d9f379ca5e8c87e66df9ae4fa8423cdaf6cc9cb44e0a2dd753f90e52b",
    "cc00a6f3d1f4ee6ab9d64d00b999b89ffcd4a4f26a2955c4705807b151ba984d",
    "643a00992517a1e47bae48b2e61655e248b9cf0e86d481a411c8508f15dba888",
    "74a22bb646fbec9351d3db1e40b810c6271ac2622fb8759be2a0abe4cc987329",
    "bff3f67590f945c3e94aaf8640f6840503979d00cd26eeac01618b8fad666623",
    "75908e2bc51627427703a7a6d7957037f4b99ef543bf647d9c2ee0eb61d99366",
    "e3e41d60eec1bb164464e99239b593ac6243d162a76d35e79c3acdf63e10257c",
    "d41b2aa147581562994723d5258c0dc0736406395d16c2401f2b674816bcc2d8",
    "040827e0add7559da74b40c1630805337ba7f8942e46b4c27e00ed1f464c436f",
    "0b4abba14a39316105e2b0b2e6d4efcc82c07830f798862a35c85d09e1035ca2",
    "cdd19e73debc2a488847161810144831da2bea5ed0dcd717876b466af84e2466",
];

#[test]
fn md6_matches_the_specification() {
    for (index, length) in LENGTHS.iter().enumerate() {
        let data = data(*length);
        let mut digest = [0; 32];
        MD6::digest(&data, &mut digest);
        assert_eq!(hex(&digest), MD6_256[index], "MD6-256 at {length}");

        let mut digest = [0; 28];
        let mut hash = MD6::new(28);
        hash.update(&data);
        hash.finalize(&mut digest);
        assert_eq!(hex(&digest), MD6_224[index], "MD6-224 at {length}");

        let mut digest = [0; 64];
        let mut hash = MD6::new(64);
        hash.update(&data);
        hash.finalize(&mut digest);
        assert_eq!(hex(&digest), MD6_512[index], "MD6-512 at {length}");

        let mut digest = [0; 32];
        let mut hash = MD6::with_key(32, &(1..=16).collect::<Vec<u8>>());
        hash.update(&data);
        hash.finalize(&mut digest);
        assert_eq!(hex(&digest), MD6_KEYED[index], "keyed at {length}");
    }
}

#[test]
fn streaming_matches_the_one_shot_call() {
    let data = data(10000);
    for split in [0, 1, 511, 512, 513, 1024, 2048, 4096, 9999, 10000] {
        let mut streamed = [0; 32];
        let mut once = [0; 32];
        let mut hash = MD6::new(32);
        hash.update(&data[..split]);
        hash.update(&data[split..]);
        hash.finalize(&mut streamed);
        MD6::digest(&data, &mut once);
        assert_eq!(streamed, once, "at {split}");
    }
}

#[test]
fn reset_restores_the_initial_state() {
    let mut hash = MD6::new(32);
    hash.update(&data(5000));
    hash.reset();
    hash.update(b"abc");
    let mut after = [0; 32];
    hash.finalize(&mut after);
    let mut expected = [0; 32];
    MD6::digest(b"abc", &mut expected);
    assert_eq!(after, expected);
}