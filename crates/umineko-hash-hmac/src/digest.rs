#[cfg(feature = "sha")]
use umineko_hash_sha::{SHA0, SHA1, SHA2_224, SHA2_256, SHA2_384, SHA2_512, SHA2_512_224, SHA2_512_256, SHA3_224, SHA3_256, SHA3_384, SHA3_512};
#[cfg(feature = "md")]
use umineko_hash_md::{MD2, MD4, MD5};
#[cfg(feature = "ripemd")]
use umineko_hash_ripemd::{RIPEMD160};
#[cfg(feature = "sm3")]
use umineko_hash_sm3::{SM3};

/// A hash the construction keys, calling it once over the message and once over that call.
pub trait Digest: Clone {
    /// The digest, as the hash itself returns it.
    type Output: AsRef<[u8]>;

    const NAME: &'static str;
    const BLOCK_SIZE: usize;
    const DIGEST_SIZE: usize;

    fn new() -> Self;

    fn builtin() -> Self;

    fn update(&mut self, data: &[u8]);

    fn finalize(self) -> Self::Output;
}

#[cfg(feature = "sha")]
impl Digest for SHA0 {
    type Output = [u8; 20];

    const NAME: &'static str = SHA0::NAME;
    const BLOCK_SIZE: usize = SHA0::BLOCK_SIZE;
    const DIGEST_SIZE: usize = SHA0::DIGEST_SIZE;

    fn new() -> Self {
        SHA0::new()
    }

    fn builtin() -> Self {
        SHA0::builtin()
    }

    fn update(&mut self, data: &[u8]) {
        SHA0::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        SHA0::finalize(self)
    }
}

#[cfg(feature = "sha")]
impl Digest for SHA1 {
    type Output = [u8; 20];

    const NAME: &'static str = SHA1::NAME;
    const BLOCK_SIZE: usize = SHA1::BLOCK_SIZE;
    const DIGEST_SIZE: usize = SHA1::DIGEST_SIZE;

    fn new() -> Self {
        SHA1::new()
    }

    fn builtin() -> Self {
        SHA1::builtin()
    }

    fn update(&mut self, data: &[u8]) {
        SHA1::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        SHA1::finalize(self)
    }
}

#[cfg(feature = "sha")]
impl Digest for SHA2_224 {
    type Output = [u8; 28];

    const NAME: &'static str = SHA2_224::NAME;
    const BLOCK_SIZE: usize = SHA2_224::BLOCK_SIZE;
    const DIGEST_SIZE: usize = SHA2_224::DIGEST_SIZE;

    fn new() -> Self {
        SHA2_224::new()
    }

    fn builtin() -> Self {
        SHA2_224::builtin()
    }

    fn update(&mut self, data: &[u8]) {
        SHA2_224::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        SHA2_224::finalize(self)
    }
}

#[cfg(feature = "sha")]
impl Digest for SHA2_256 {
    type Output = [u8; 32];

    const NAME: &'static str = SHA2_256::NAME;
    const BLOCK_SIZE: usize = SHA2_256::BLOCK_SIZE;
    const DIGEST_SIZE: usize = SHA2_256::DIGEST_SIZE;

    fn new() -> Self {
        SHA2_256::new()
    }

    fn builtin() -> Self {
        SHA2_256::builtin()
    }

    fn update(&mut self, data: &[u8]) {
        SHA2_256::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        SHA2_256::finalize(self)
    }
}

#[cfg(feature = "sha")]
impl Digest for SHA2_384 {
    type Output = [u8; 48];

    const NAME: &'static str = SHA2_384::NAME;
    const BLOCK_SIZE: usize = SHA2_384::BLOCK_SIZE;
    const DIGEST_SIZE: usize = SHA2_384::DIGEST_SIZE;

    fn new() -> Self {
        SHA2_384::new()
    }

    fn builtin() -> Self {
        SHA2_384::builtin()
    }

    fn update(&mut self, data: &[u8]) {
        SHA2_384::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        SHA2_384::finalize(self)
    }
}

#[cfg(feature = "sha")]
impl Digest for SHA2_512 {
    type Output = [u8; 64];

    const NAME: &'static str = SHA2_512::NAME;
    const BLOCK_SIZE: usize = SHA2_512::BLOCK_SIZE;
    const DIGEST_SIZE: usize = SHA2_512::DIGEST_SIZE;

    fn new() -> Self {
        SHA2_512::new()
    }

    fn builtin() -> Self {
        SHA2_512::builtin()
    }

    fn update(&mut self, data: &[u8]) {
        SHA2_512::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        SHA2_512::finalize(self)
    }
}

#[cfg(feature = "sha")]
impl Digest for SHA2_512_224 {
    type Output = [u8; 28];

    const NAME: &'static str = SHA2_512_224::NAME;
    const BLOCK_SIZE: usize = SHA2_512_224::BLOCK_SIZE;
    const DIGEST_SIZE: usize = SHA2_512_224::DIGEST_SIZE;

    fn new() -> Self {
        SHA2_512_224::new()
    }

    fn builtin() -> Self {
        SHA2_512_224::builtin()
    }

    fn update(&mut self, data: &[u8]) {
        SHA2_512_224::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        SHA2_512_224::finalize(self)
    }
}

#[cfg(feature = "sha")]
impl Digest for SHA2_512_256 {
    type Output = [u8; 32];

    const NAME: &'static str = SHA2_512_256::NAME;
    const BLOCK_SIZE: usize = SHA2_512_256::BLOCK_SIZE;
    const DIGEST_SIZE: usize = SHA2_512_256::DIGEST_SIZE;

    fn new() -> Self {
        SHA2_512_256::new()
    }

    fn builtin() -> Self {
        SHA2_512_256::builtin()
    }

    fn update(&mut self, data: &[u8]) {
        SHA2_512_256::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        SHA2_512_256::finalize(self)
    }
}

#[cfg(feature = "sha")]
impl Digest for SHA3_224 {
    type Output = [u8; 28];

    const NAME: &'static str = SHA3_224::NAME;
    const BLOCK_SIZE: usize = SHA3_224::BLOCK_SIZE;
    const DIGEST_SIZE: usize = SHA3_224::DIGEST_SIZE;

    fn new() -> Self {
        SHA3_224::new()
    }

    fn builtin() -> Self {
        SHA3_224::builtin()
    }

    fn update(&mut self, data: &[u8]) {
        SHA3_224::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        SHA3_224::finalize(self)
    }
}

#[cfg(feature = "sha")]
impl Digest for SHA3_256 {
    type Output = [u8; 32];

    const NAME: &'static str = SHA3_256::NAME;
    const BLOCK_SIZE: usize = SHA3_256::BLOCK_SIZE;
    const DIGEST_SIZE: usize = SHA3_256::DIGEST_SIZE;

    fn new() -> Self {
        SHA3_256::new()
    }

    fn builtin() -> Self {
        SHA3_256::builtin()
    }

    fn update(&mut self, data: &[u8]) {
        SHA3_256::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        SHA3_256::finalize(self)
    }
}

#[cfg(feature = "sha")]
impl Digest for SHA3_384 {
    type Output = [u8; 48];

    const NAME: &'static str = SHA3_384::NAME;
    const BLOCK_SIZE: usize = SHA3_384::BLOCK_SIZE;
    const DIGEST_SIZE: usize = SHA3_384::DIGEST_SIZE;

    fn new() -> Self {
        SHA3_384::new()
    }

    fn builtin() -> Self {
        SHA3_384::builtin()
    }

    fn update(&mut self, data: &[u8]) {
        SHA3_384::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        SHA3_384::finalize(self)
    }
}

#[cfg(feature = "sha")]
impl Digest for SHA3_512 {
    type Output = [u8; 64];

    const NAME: &'static str = SHA3_512::NAME;
    const BLOCK_SIZE: usize = SHA3_512::BLOCK_SIZE;
    const DIGEST_SIZE: usize = SHA3_512::DIGEST_SIZE;

    fn new() -> Self {
        SHA3_512::new()
    }

    fn builtin() -> Self {
        SHA3_512::builtin()
    }

    fn update(&mut self, data: &[u8]) {
        SHA3_512::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        SHA3_512::finalize(self)
    }
}

#[cfg(feature = "md")]
impl Digest for MD2 {
    type Output = [u8; 16];

    const NAME: &'static str = MD2::NAME;
    const BLOCK_SIZE: usize = MD2::BLOCK_SIZE;
    const DIGEST_SIZE: usize = MD2::DIGEST_SIZE;

    fn new() -> Self {
        MD2::new()
    }

    fn builtin() -> Self {
        MD2::builtin()
    }

    fn update(&mut self, data: &[u8]) {
        MD2::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        MD2::finalize(self)
    }
}

#[cfg(feature = "md")]
impl Digest for MD4 {
    type Output = [u8; 16];

    const NAME: &'static str = MD4::NAME;
    const BLOCK_SIZE: usize = MD4::BLOCK_SIZE;
    const DIGEST_SIZE: usize = MD4::DIGEST_SIZE;

    fn new() -> Self {
        MD4::new()
    }

    fn builtin() -> Self {
        MD4::builtin()
    }

    fn update(&mut self, data: &[u8]) {
        MD4::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        MD4::finalize(self)
    }
}

#[cfg(feature = "md")]
impl Digest for MD5 {
    type Output = [u8; 16];

    const NAME: &'static str = MD5::NAME;
    const BLOCK_SIZE: usize = MD5::BLOCK_SIZE;
    const DIGEST_SIZE: usize = MD5::DIGEST_SIZE;

    fn new() -> Self {
        MD5::new()
    }

    fn builtin() -> Self {
        MD5::builtin()
    }

    fn update(&mut self, data: &[u8]) {
        MD5::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        MD5::finalize(self)
    }
}

#[cfg(feature = "ripemd")]
impl Digest for RIPEMD160 {
    type Output = [u8; 20];

    const NAME: &'static str = RIPEMD160::NAME;
    const BLOCK_SIZE: usize = RIPEMD160::BLOCK_SIZE;
    const DIGEST_SIZE: usize = RIPEMD160::DIGEST_SIZE;

    fn new() -> Self {
        RIPEMD160::new()
    }

    fn builtin() -> Self {
        RIPEMD160::builtin()
    }

    fn update(&mut self, data: &[u8]) {
        RIPEMD160::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        RIPEMD160::finalize(self)
    }
}

#[cfg(feature = "sm3")]
impl Digest for SM3 {
    type Output = [u8; 32];

    const NAME: &'static str = SM3::NAME;
    const BLOCK_SIZE: usize = SM3::BLOCK_SIZE;
    const DIGEST_SIZE: usize = SM3::DIGEST_SIZE;

    fn new() -> Self {
        SM3::new()
    }

    fn builtin() -> Self {
        SM3::builtin()
    }

    fn update(&mut self, data: &[u8]) {
        SM3::update(self, data)
    }

    fn finalize(self) -> Self::Output {
        SM3::finalize(self)
    }
}
