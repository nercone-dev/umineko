use core::ffi::{c_char, c_int};

use umineko::provider::{ProviderCategory, Providers};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum umineko_provider_category_t {
    UMINEKO_PROVIDER_IP = 0,
    UMINEKO_PROVIDER_ICMP = 1,
    UMINEKO_PROVIDER_UDS = 2,
    UMINEKO_PROVIDER_TCP = 3,
    UMINEKO_PROVIDER_UDP = 4,
    UMINEKO_PROVIDER_TLS = 5,
    UMINEKO_PROVIDER_QUIC = 6,
    UMINEKO_PROVIDER_HTTP = 7,
    UMINEKO_PROVIDER_DNS = 8,
    UMINEKO_PROVIDER_HASH = 9,
    UMINEKO_PROVIDER_CIPHER = 10,
    UMINEKO_PROVIDER_SIGNATURE = 11,
    UMINEKO_PROVIDER_EXCHANGE = 12,
    UMINEKO_PROVIDER_KDF = 13,
    UMINEKO_PROVIDER_CODEC = 14,
}

impl umineko_provider_category_t {
    pub fn category(self) -> ProviderCategory {
        ProviderCategory::ALL[self as usize]
    }

    #[cfg(feature = "auto")]
    #[unsafe(no_mangle)]
    pub extern "C" fn umineko_provider_install() -> bool {
        umineko::auto::Auto::install().is_ok()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn umineko_provider_available(category: umineko_provider_category_t) -> bool {
        Providers::available(category.category())
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_provider_names(category: umineko_provider_category_t, out: *mut *const c_char, capacity: usize) -> usize {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_provider_set_enabled(name: *const c_char, enabled: bool) -> bool {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_provider_set_priority(name: *const c_char, priority: c_int) -> bool {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_provider_set_order(category: umineko_provider_category_t, names: *const *const c_char, count: usize) -> bool {
        todo!()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn umineko_provider_set_fallback(category: umineko_provider_category_t, fallback: umineko_provider_fallback_t) -> bool {
        todo!()
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum umineko_provider_fallback_t {
    UMINEKO_PROVIDER_FALLBACK_NEVER = 0,
    UMINEKO_PROVIDER_FALLBACK_DECLINED = 1,
    UMINEKO_PROVIDER_FALLBACK_ANY = 2,
}
