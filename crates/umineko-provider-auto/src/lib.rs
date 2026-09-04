//! Automatic provider selection.

#![no_std]

extern crate alloc;

pub mod auto;

#[cfg(target_os = "linux")]
pub use umineko_provider_linux as linux;
#[cfg(target_vendor = "apple")]
pub use umineko_provider_darwin as darwin;
#[cfg(target_os = "windows")]
pub use umineko_provider_windows as windows;
#[cfg(target_os = "android")]
pub use umineko_provider_android as android;
#[cfg(target_os = "freebsd")]
pub use umineko_provider_freebsd as freebsd;
#[cfg(target_os = "openbsd")]
pub use umineko_provider_openbsd as openbsd;
#[cfg(target_os = "netbsd")]
pub use umineko_provider_netbsd as netbsd;
#[cfg(target_os = "wasi")]
pub use umineko_provider_wasi as wasi;

#[cfg(target_os = "linux")]
pub use umineko_provider_linux as current;
#[cfg(target_vendor = "apple")]
pub use umineko_provider_darwin as current;
#[cfg(target_os = "windows")]
pub use umineko_provider_windows as current;
#[cfg(target_os = "android")]
pub use umineko_provider_android as current;
#[cfg(target_os = "freebsd")]
pub use umineko_provider_freebsd as current;
#[cfg(target_os = "openbsd")]
pub use umineko_provider_openbsd as current;
#[cfg(target_os = "netbsd")]
pub use umineko_provider_netbsd as current;
#[cfg(target_os = "wasi")]
pub use umineko_provider_wasi as current;

pub use auto::{Auto};
