//! Shared helpers.

#![no_std]

extern crate alloc;

#[cfg(feature = "bytes")]
pub mod bytes;

#[cfg(feature = "buffer")]
pub mod buffer;

pub mod provider {
    pub mod base;
    pub mod registry;
    pub mod backend;
    pub mod hash;
    pub mod cipher;
    pub mod signature;
    pub mod exchange;
    pub mod kdf;
    pub mod codec;

    pub use base::{Provider, ProviderCategory, ProviderHandle, ProviderError, ProviderInterest, ProviderOrder, ProviderFallback, ProviderPolicy};
    pub use registry::{ProviderRegistry, ProviderEntry, ProviderSelection, ProviderLock};
    pub use backend::{ProviderBackend, ProviderOpening};
    pub use hash::{HashProvider, HashProviderRequest, HashProviders};
    pub use cipher::{CipherProvider, CipherProviderRequest, CipherProviders};
    pub use signature::{SignatureProvider, SignatureProviderRequest, SignatureProviders};
    pub use exchange::{ExchangeProvider, ExchangeProviderRequest, ExchangeProviders};
    pub use kdf::{KDFProvider, KDFProviderRequest, KDFProviderInputs, KDFProviders};
    pub use codec::{CodecProvider, CodecProviderRequest, CodecDirection, CodecProviders};
}

#[cfg(feature = "bytes")]
pub use bytes::Bytes;

#[cfg(feature = "buffer")]
pub use buffer::Buffer;
