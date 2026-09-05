use core::marker::PhantomData;

use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

use crate::digest::Digest;
use crate::errors::HMACError;

/// One block of a hash, held without an allocator, and so without the size of that hash in its type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HMACBuffer {
    bytes: [u8; Self::MAXIMUM_SIZE],
    size: usize,
}

impl HMACBuffer {
    /// The largest block or digest the buffer holds. The widest block standardised is the one of SHAKE128, of one hundred and sixty-eight bytes; a hash wider than this cannot be keyed without an allocator, and asking for it panics.
    pub const MAXIMUM_SIZE: usize = 256;

    /// A buffer of the given size, holding zeroes.
    pub fn new(size: usize) -> Self {
        Self { bytes: [0; Self::MAXIMUM_SIZE], size }
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.size]
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.size]
    }

    /// Puts the data at the front of the buffer and leaves the rest of it zero.
    pub fn fill(&mut self, data: &[u8]) {
        self.bytes = [0; Self::MAXIMUM_SIZE];
        self.bytes[..data.len()].copy_from_slice(data);
    }

    /// The buffer with every byte exclusive-ored with the pad, which is how both blocks of the construction are made.
    pub fn padded(&self, pad: u8) -> Self {
        let mut buffer = *self;
        for byte in buffer.bytes.iter_mut() {
            *byte ^= pad;
        }
        buffer
    }
}

/// A hash keyed by nesting one call inside another, over the key padded to a block.
#[derive(Debug)]
pub struct HMAC<D: Digest> {
    inner: D,
    outer: D,
    initial: D,
    backend: ProviderBackend<dyn HashProvider>,
}

impl<D: Digest> HMAC<D> {
    pub const NAME: &'static str = "HMAC";
    pub const INNER_PAD: u8 = 0x36;
    pub const OUTER_PAD: u8 = 0x5C;

    pub fn new(key: &[u8]) -> Self {
        match HashProviders::backend(&Self::request(key)) {
            ProviderBackend::Builtin => Self::keyed(key, D::new(), D::new()),
            backend => Self { inner: D::builtin(), outer: D::builtin(), initial: D::builtin(), backend },
        }
    }

    pub fn builtin(key: &[u8]) -> Self {
        Self::keyed(key, D::builtin(), D::builtin())
    }

    /// The construction over two fresh hashes, one fed the block of the inner call and one the block of the outer call.
    pub fn keyed(key: &[u8], mut inner: D, mut outer: D) -> Self {
        let block = Self::shorten(key);
        inner.update(block.padded(Self::INNER_PAD).bytes());
        outer.update(block.padded(Self::OUTER_PAD).bytes());
        Self { initial: inner.clone(), inner, outer, backend: ProviderBackend::Builtin }
    }

    pub fn request(key: &[u8]) -> HashProviderRequest<'_> {
        HashProviderRequest::new(Self::NAME).with_digest(D::NAME).with_key(key)
    }

    pub fn digest_size() -> usize {
        D::DIGEST_SIZE
    }

    pub fn block_size() -> usize {
        D::BLOCK_SIZE
    }

    /// The key held in one block, hashed down first when it is longer than that block.
    pub fn shorten(key: &[u8]) -> HMACBuffer {
        let mut block = HMACBuffer::new(D::BLOCK_SIZE);
        match key.len() > D::BLOCK_SIZE {
            true => {
                let mut hash = D::new();
                hash.update(key);
                block.fill(hash.finalize().as_ref());
            }
            false => block.fill(key),
        }
        block
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => self.inner.update(data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    /// Writes as much of the tag as the output holds, truncating it when the output is shorter, and returns how much was written.
    pub fn finalize(self, tag: &mut [u8]) -> usize {
        let Self { inner, mut outer, initial: _, backend } = self;
        match &backend {
            ProviderBackend::Builtin => {
                outer.update(inner.finalize().as_ref());
                let digest = outer.finalize();
                let length = tag.len().min(digest.as_ref().len());
                tag[..length].copy_from_slice(&digest.as_ref()[..length]);
                length
            }
            ProviderBackend::Handle { provider, handle } => provider.finalize(*handle, tag),
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => self.inner = self.initial.clone(),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    /// Compares the tag against the one computed, in a time that does not depend on where the two differ.
    pub fn verify(self, tag: &[u8]) -> Result<(), HMACError> {
        if tag.is_empty() || tag.len() > D::DIGEST_SIZE {
            return Err(HMACError::Length);
        }
        let mut computed = HMACBuffer::new(D::DIGEST_SIZE);
        if self.finalize(computed.bytes_mut()) < tag.len() {
            return Err(HMACError::Length);
        }
        let mut difference = 0;
        for (left, right) in computed.bytes().iter().zip(tag) {
            difference |= left ^ right;
        }
        match difference {
            0 => Ok(()),
            _ => Err(HMACError::Authentication),
        }
    }

    pub fn tag(key: &[u8], data: &[u8], tag: &mut [u8]) -> usize {
        match HashProviders::digest(&Self::request(key), data, tag) {
            Some(length) => length,
            None => {
                let mut mac = Self::keyed(key, D::new(), D::new());
                mac.update(data);
                mac.finalize(tag)
            }
        }
    }

    pub fn authenticate(key: &[u8], data: &[u8], tag: &[u8]) -> Result<(), HMACError> {
        let mut mac = Self::new(key);
        mac.update(data);
        mac.verify(tag)
    }
}

impl<D: Digest> Clone for HMAC<D> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone(), outer: self.outer.clone(), initial: self.initial.clone(), backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

/// The construction with no key bound to it yet, which a key derivation calls once for every block, with a key of its own each time.
#[derive(Debug)]
pub struct HMACFunction<D: Digest> {
    digest: PhantomData<D>,
}

impl<D: Digest> HMACFunction<D> {
    pub fn new() -> Self {
        Self { digest: PhantomData }
    }

    pub fn name(&self) -> &'static str {
        HMAC::<D>::NAME
    }

    pub fn digest(&self) -> &'static str {
        D::NAME
    }

    pub fn output_size(&self) -> usize {
        D::DIGEST_SIZE
    }

    pub fn block_size(&self) -> usize {
        D::BLOCK_SIZE
    }

    pub fn compute(&self, key: &[u8], data: &[u8], output: &mut [u8]) -> usize {
        HMAC::<D>::tag(key, data, output)
    }
}

impl<D: Digest> Clone for HMACFunction<D> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<D: Digest> Copy for HMACFunction<D> {}

/// Two functions over the same hash are the same function, since neither of them holds anything.
impl<D: Digest> PartialEq for HMACFunction<D> {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl<D: Digest> Eq for HMACFunction<D> {}

impl<D: Digest> Default for HMACFunction<D> {
    fn default() -> Self {
        Self::new()
    }
}
