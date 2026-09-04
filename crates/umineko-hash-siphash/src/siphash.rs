use core::fmt;

use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SipHashRounds {
    pub compression: u8,
    pub finalization: u8,
}

impl SipHashRounds {
    pub const SIPHASH_2_4: Self = Self { compression: 2, finalization: 4 };
    pub const SIPHASH_1_3: Self = Self { compression: 1, finalization: 3 };

    pub fn name(&self) -> Option<&'static str> {
        match *self {
            Self::SIPHASH_2_4 => Some("SipHash-2-4"),
            Self::SIPHASH_1_3 => Some("SipHash-1-3"),
            _ => None,
        }
    }
}

impl fmt::Display for SipHashRounds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SipHash-{}-{}", self.compression, self.finalization)
    }
}

#[derive(Debug)]
pub struct SipHash {
    rounds: SipHashRounds,
    state: [u64; 4],
    buffer: [u8; 8],
    length: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SipHash {
    pub const DIGEST_SIZE: usize = 8;
    pub const KEY_SIZE: usize = 16;

    pub fn new(rounds: SipHashRounds, key: &[u8; 16]) -> Self {
        let backend = match rounds.name() {
            Some(name) => HashProviders::backend(&HashProviderRequest::new(name).with_key(key)),
            None => ProviderBackend::Builtin,
        };
        match backend {
            ProviderBackend::Builtin => todo!(),
            backend => Self { rounds, state: [0; 4], buffer: [0; 8], length: 0, backend },
        }
    }

    pub fn rounds(&self) -> SipHashRounds {
        self.rounds
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> u64 {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; Self::DIGEST_SIZE];
                provider.finalize(*handle, &mut digest);
                u64::from_be_bytes(digest)
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(rounds: SipHashRounds, key: &[u8; 16], data: &[u8]) -> u64 {
        let mut digest = [0; Self::DIGEST_SIZE];
        match rounds.name().and_then(|name| HashProviders::digest(&HashProviderRequest::new(name).with_key(key), data, &mut digest)) {
            Some(_) => u64::from_be_bytes(digest),
            None => todo!(),
        }
    }
}

impl Clone for SipHash {
    fn clone(&self) -> Self {
        Self { rounds: self.rounds, state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}
