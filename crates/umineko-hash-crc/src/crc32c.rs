use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

use crate::crc32::CRC32Table;

#[derive(Debug)]
pub struct CRC32C {
    value: u32,
    backend: ProviderBackend<dyn HashProvider>,
}

impl CRC32C {
    pub const NAME: &'static str = "CRC-32C";
    pub const DIGEST_SIZE: usize = 4;
    pub const POLYNOMIAL: u32 = 0x1EDC_6F41;
    pub const INITIAL: u32 = 0xFFFF_FFFF;
    pub const FINAL_XOR: u32 = 0xFFFF_FFFF;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { value: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { value: Self::INITIAL, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    /// The table this polynomial folds its nibbles through.
    pub const TABLE: CRC32Table = CRC32Table::new(Self::POLYNOMIAL);

    /// Folds `data` into the register, which starts at `INITIAL` and holds no final transform.
    pub fn absorb(register: u32, data: &[u8]) -> u32 {
        Self::TABLE.absorb(register, data, true)
    }

    /// Applies the final transform to a register produced by `absorb`.
    pub fn squeeze(register: u32) -> u32 {
        register.reverse_bits() ^ Self::FINAL_XOR
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => self.value = Self::absorb(self.value, data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> u32 {
        match &self.backend {
            ProviderBackend::Builtin => Self::squeeze(self.value),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; Self::DIGEST_SIZE];
                provider.finalize(*handle, &mut digest);
                u32::from_be_bytes(digest)
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => self.value = Self::INITIAL,
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8]) -> u32 {
        let mut digest = [0; Self::DIGEST_SIZE];
        match HashProviders::digest(&Self::request(), data, &mut digest) {
            Some(_) => u32::from_be_bytes(digest),
            None => {
                let mut hash = Self::builtin();
                hash.update(data);
                hash.finalize()
            }
        }
    }
}

impl Clone for CRC32C {
    fn clone(&self) -> Self {
        Self { value: self.value, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for CRC32C {
    fn default() -> Self {
        Self::new()
    }
}
