use umineko_crypto_dsa::DSA;

#[test]
fn parameter_sizes_follow_fips_186_4() {
    let expected = [(DSA::V1024_160, 1024, 160), (DSA::V2048_224, 2048, 224), (DSA::V2048_256, 2048, 256), (DSA::V3072_256, 3072, 256)];
    for (variant, bits, order_bits) in expected {
        assert_eq!(variant.bits(), bits, "{variant}");
        assert_eq!(variant.order_bits(), order_bits, "{variant}");
        assert_eq!(DSA::from_name(variant.as_str()), Some(variant));
        assert_eq!(variant.request().algorithm, variant.as_str());
    }
}
