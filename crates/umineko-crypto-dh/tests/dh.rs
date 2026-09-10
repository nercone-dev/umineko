use umineko_crypto_dh::{DH, DHGroup};

#[test]
fn group_sizes_follow_rfc7919_rfc3526_and_rfc2409() {
    let expected = [
        (DHGroup::FFDHE2048, 2048, "ffdhe2048"),
        (DHGroup::FFDHE3072, 3072, "ffdhe3072"),
        (DHGroup::FFDHE4096, 4096, "ffdhe4096"),
        (DHGroup::FFDHE6144, 6144, "ffdhe6144"),
        (DHGroup::FFDHE8192, 8192, "ffdhe8192"),
        (DHGroup::MODP768, 768, "modp768"),
        (DHGroup::MODP1024, 1024, "modp1024"),
        (DHGroup::MODP1536, 1536, "modp1536"),
        (DHGroup::MODP2048, 2048, "modp2048"),
        (DHGroup::MODP3072, 3072, "modp3072"),
        (DHGroup::MODP4096, 4096, "modp4096"),
        (DHGroup::MODP6144, 6144, "modp6144"),
        (DHGroup::MODP8192, 8192, "modp8192"),
    ];
    for (group, bits, name) in expected {
        assert_eq!(group.bits(), bits, "{group}");
        assert_eq!(DH::Group(group).bits(), bits, "{group}");
        assert_eq!(group.as_str(), name);
        assert_eq!(DHGroup::from_name(name), Some(group));
    }
}
