use umineko_provider::Providers;
use umineko_provider_auto::Auto;

#[test]
fn the_current_platform_provider_is_installed_before_main() {
    assert!(Auto::installed());
    let name = Auto::name().expect("this target has a platform provider");
    assert!(Providers::registered(name));
    assert_eq!(Auto::install(), Ok(()));
    assert!(Auto::uninstall());
    assert!(!Auto::installed());
    assert!(!Providers::registered(name));
    assert!(!Auto::uninstall());
    assert_eq!(Auto::install(), Ok(()));
    assert!(Providers::registered(name));
}
