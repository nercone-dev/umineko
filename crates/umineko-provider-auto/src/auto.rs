use core::sync::atomic::{AtomicBool, Ordering};

use umineko_provider::{Providers, ProviderError};

pub struct Auto;

impl Auto {
    pub fn flag() -> &'static AtomicBool {
        static INSTALLED: AtomicBool = AtomicBool::new(false);
        &INSTALLED
    }

    pub fn installed() -> bool {
        Self::flag().load(Ordering::Acquire)
    }

    pub fn name() -> Option<&'static str> {
        #[cfg(target_os = "linux")]
        return Some(crate::current::LinuxProvider::NAME);
        #[cfg(target_vendor = "apple")]
        return Some(crate::current::DarwinProvider::NAME);
        #[cfg(target_os = "windows")]
        return Some(crate::current::WindowsProvider::NAME);
        #[cfg(target_os = "android")]
        return Some(crate::current::AndroidProvider::NAME);
        #[cfg(target_os = "freebsd")]
        return Some(crate::current::FreeBSDProvider::NAME);
        #[cfg(target_os = "openbsd")]
        return Some(crate::current::OpenBSDProvider::NAME);
        #[cfg(target_os = "netbsd")]
        return Some(crate::current::NetBSDProvider::NAME);
        #[cfg(target_os = "wasi")]
        return Some(crate::current::WASIProvider::NAME);
        #[allow(unreachable_code)]
        None
    }

    pub fn register() -> Result<(), ProviderError> {
        #[cfg(target_os = "linux")]
        return Providers::register(alloc::sync::Arc::new(crate::current::LinuxProvider::new()));
        #[cfg(target_vendor = "apple")]
        return Providers::register(alloc::sync::Arc::new(crate::current::DarwinProvider::new()));
        #[cfg(target_os = "windows")]
        return Providers::register(alloc::sync::Arc::new(crate::current::WindowsProvider::new()));
        #[cfg(target_os = "android")]
        return Providers::register(alloc::sync::Arc::new(crate::current::AndroidProvider::new()));
        #[cfg(target_os = "freebsd")]
        return Providers::register(alloc::sync::Arc::new(crate::current::FreeBSDProvider::new()));
        #[cfg(target_os = "openbsd")]
        return Providers::register(alloc::sync::Arc::new(crate::current::OpenBSDProvider::new()));
        #[cfg(target_os = "netbsd")]
        return Providers::register(alloc::sync::Arc::new(crate::current::NetBSDProvider::new()));
        #[cfg(target_os = "wasi")]
        return Providers::register(alloc::sync::Arc::new(crate::current::WASIProvider::new()));
        #[allow(unreachable_code)]
        Err(ProviderError::Unavailable)
    }

    pub fn install() -> Result<(), ProviderError> {
        if Self::flag().swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        match Self::register() {
            Ok(()) => Ok(()),
            Err(error) => {
                Self::flag().store(false, Ordering::Release);
                Err(error)
            }
        }
    }

    pub fn uninstall() -> bool {
        if !Self::flag().swap(false, Ordering::AcqRel) {
            return false;
        }
        Self::name().is_some_and(Providers::unregister)
    }

    pub extern "C" fn entry() {
        let _ = Self::install();
    }

    #[cfg(feature = "constructor")]
    pub const CONSTRUCTOR: () = {
        #[used]
        #[cfg_attr(any(target_os = "linux", target_os = "android", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "wasi"), unsafe(link_section = ".init_array"))]
        #[cfg_attr(target_vendor = "apple", unsafe(link_section = "__DATA,__mod_init_func"))]
        #[cfg_attr(target_os = "windows", unsafe(link_section = ".CRT$XCU"))]
        static ENTRY: extern "C" fn() = Auto::entry;
    };
}
