use umineko_provider::{ProviderCategory, Providers};
use umineko_provider_auto::Auto;

#[cfg(target_os = "linux")]
const CATEGORIES: &[ProviderCategory] = &[ProviderCategory::IP, ProviderCategory::ICMP, ProviderCategory::UDS, ProviderCategory::TCP, ProviderCategory::UDP, ProviderCategory::TLS, ProviderCategory::Hash, ProviderCategory::Cipher, ProviderCategory::Signature, ProviderCategory::Exchange, ProviderCategory::KDF];
#[cfg(target_vendor = "apple")]
const CATEGORIES: &[ProviderCategory] = &[ProviderCategory::IP, ProviderCategory::ICMP, ProviderCategory::UDS, ProviderCategory::TCP, ProviderCategory::UDP, ProviderCategory::TLS, ProviderCategory::QUIC, ProviderCategory::Hash, ProviderCategory::Cipher, ProviderCategory::Signature, ProviderCategory::Exchange, ProviderCategory::KDF];
#[cfg(target_os = "windows")]
const CATEGORIES: &[ProviderCategory] = &[ProviderCategory::IP, ProviderCategory::ICMP, ProviderCategory::UDS, ProviderCategory::TCP, ProviderCategory::UDP, ProviderCategory::TLS, ProviderCategory::QUIC, ProviderCategory::Hash, ProviderCategory::Cipher, ProviderCategory::Signature, ProviderCategory::Exchange, ProviderCategory::KDF];
#[cfg(target_os = "android")]
const CATEGORIES: &[ProviderCategory] = &[ProviderCategory::IP, ProviderCategory::ICMP, ProviderCategory::UDS, ProviderCategory::TCP, ProviderCategory::UDP, ProviderCategory::Cipher, ProviderCategory::Signature, ProviderCategory::Exchange, ProviderCategory::KDF];
#[cfg(target_os = "freebsd")]
const CATEGORIES: &[ProviderCategory] = &[ProviderCategory::IP, ProviderCategory::ICMP, ProviderCategory::UDS, ProviderCategory::TCP, ProviderCategory::UDP, ProviderCategory::TLS, ProviderCategory::Hash, ProviderCategory::Cipher, ProviderCategory::Signature, ProviderCategory::Exchange, ProviderCategory::KDF];
#[cfg(target_os = "openbsd")]
const CATEGORIES: &[ProviderCategory] = &[ProviderCategory::IP, ProviderCategory::ICMP, ProviderCategory::UDS, ProviderCategory::TCP, ProviderCategory::UDP, ProviderCategory::TLS, ProviderCategory::Hash, ProviderCategory::Cipher, ProviderCategory::Signature, ProviderCategory::Exchange, ProviderCategory::KDF];
#[cfg(target_os = "netbsd")]
const CATEGORIES: &[ProviderCategory] = &[ProviderCategory::IP, ProviderCategory::ICMP, ProviderCategory::UDS, ProviderCategory::TCP, ProviderCategory::UDP, ProviderCategory::TLS, ProviderCategory::Hash, ProviderCategory::Cipher, ProviderCategory::Signature, ProviderCategory::Exchange, ProviderCategory::KDF];
#[cfg(target_os = "wasi")]
const CATEGORIES: &[ProviderCategory] = &[ProviderCategory::TCP, ProviderCategory::UDP, ProviderCategory::HTTP];
#[cfg(not(any(target_os = "linux", target_vendor = "apple", target_os = "windows", target_os = "android", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "wasi")))]
const CATEGORIES: &[ProviderCategory] = &[];

#[test]
fn the_current_platform_provider_covers_exactly_its_declared_categories() {
    assert_eq!(Auto::name().is_some(), !CATEGORIES.is_empty());
    for category in ProviderCategory::ALL {
        assert_eq!(Providers::available(category), CATEGORIES.contains(&category), "{}", category.as_str());
    }
    assert_eq!(Auto::uninstall(), Auto::name().is_some());
    for category in ProviderCategory::ALL {
        assert!(!Providers::available(category), "{}", category.as_str());
    }
    assert_eq!(Auto::install(), Ok(()));
    for category in ProviderCategory::ALL {
        assert_eq!(Providers::available(category), CATEGORIES.contains(&category), "{}", category.as_str());
    }
}
