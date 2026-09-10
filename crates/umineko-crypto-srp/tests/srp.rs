use umineko_crypto_srp::SRPGroup;

#[test]
fn groups_follow_rfc5054_appendix_a() {
    let expected = [(SRPGroup::V1024, 1024, 2), (SRPGroup::V1536, 1536, 2), (SRPGroup::V2048, 2048, 2), (SRPGroup::V3072, 3072, 5), (SRPGroup::V4096, 4096, 5), (SRPGroup::V6144, 6144, 5), (SRPGroup::V8192, 8192, 19)];
    for (group, bits, generator) in expected {
        assert_eq!(group.bits(), bits, "{group}");
        assert_eq!(group.generator(), generator, "{group}");
        assert_eq!(SRPGroup::from_name(group.as_str()), Some(group));
    }
}
