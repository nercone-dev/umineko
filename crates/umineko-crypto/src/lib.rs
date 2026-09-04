//! Cryptography.

#![no_std]

#[cfg(feature = "rsa")]
pub use umineko_crypto_rsa as rsa;
#[cfg(feature = "des")]
pub use umineko_crypto_des as des;
#[cfg(feature = "aes")]
pub use umineko_crypto_aes as aes;
#[cfg(feature = "chacha20")]
pub use umineko_crypto_chacha20 as chacha20;
#[cfg(feature = "poly1305")]
pub use umineko_crypto_poly1305 as poly1305;
#[cfg(feature = "ecdsa")]
pub use umineko_crypto_ecdsa as ecdsa;
#[cfg(feature = "eddsa")]
pub use umineko_crypto_eddsa as eddsa;
#[cfg(feature = "ecdh")]
pub use umineko_crypto_ecdh as ecdh;
#[cfg(feature = "mlkem")]
pub use umineko_crypto_mlkem as mlkem;
#[cfg(feature = "mldsa")]
pub use umineko_crypto_mldsa as mldsa;
#[cfg(feature = "slhdsa")]
pub use umineko_crypto_slhdsa as slhdsa;
#[cfg(feature = "hqc")]
pub use umineko_crypto_hqc as hqc;
#[cfg(feature = "ascon")]
pub use umineko_crypto_ascon as ascon;
#[cfg(feature = "hkdf")]
pub use umineko_crypto_hkdf as hkdf;
#[cfg(feature = "scrypt")]
pub use umineko_crypto_scrypt as scrypt;
#[cfg(feature = "pbkdf2")]
pub use umineko_crypto_pbkdf2 as pbkdf2;
#[cfg(feature = "argon2")]
pub use umineko_crypto_argon2 as argon2;
#[cfg(feature = "hybrid")]
pub use umineko_crypto_hybrid as hybrid;
