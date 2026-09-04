use umineko::provider::Providers;

#[test]
fn the_platform_provider_is_registered_without_referencing_the_auto_crate() {
    assert!(!Providers::names().is_empty());
}
