use umineko_crypto_ibs::IBS;

#[test]
fn object_identifiers_follow_draft_wang_tls_raw_public_key_with_ibc() {
    let expected = [(IBS::IBS1, "1.0.14888.3.0.7"), (IBS::IBS2, "1.0.14888.3.0.8"), (IBS::ChineseIBS, "1.2.156.10197.1.302.1")];
    assert_eq!(IBS::ALL.len(), expected.len());
    for (variant, identifier) in expected {
        assert_eq!(variant.object_identifier(), identifier);
        assert_eq!(IBS::from_object_identifier(identifier), Some(variant));
        assert_eq!(IBS::from_name(variant.as_str()), Some(variant));
    }
    assert_eq!(IBS::from_object_identifier("1.0.14888.3.0.9"), None);
}
