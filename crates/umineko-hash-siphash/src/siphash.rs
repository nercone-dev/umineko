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
    key: [u8; 16],
    state: [u64; 4],
    buffer: [u8; 8],
    length: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SipHash {
    pub const DIGEST_SIZE: usize = 8;
    pub const KEY_SIZE: usize = 16;
    pub const BLOCK_SIZE: usize = 8;
    /// The four halves of "somepseudorandomlygeneratedbytes", which the key is folded into.
    pub const INITIAL: [u64; 4] = [0x736F_6D65_7073_6575, 0x646F_7261_6E64_6F6D, 0x6C79_6765_6E65_7261, 0x7465_6462_7974_6573];

    pub fn new(rounds: SipHashRounds, key: &[u8; 16]) -> Self {
        let backend = match rounds.name() {
            Some(name) => HashProviders::backend(&HashProviderRequest::new(name).with_key(key)),
            None => ProviderBackend::Builtin,
        };
        match backend {
            ProviderBackend::Builtin => Self::builtin(rounds, key),
            backend => Self { rounds, key: *key, state: [0; 4], buffer: [0; 8], length: 0, backend },
        }
    }

    pub fn builtin(rounds: SipHashRounds, key: &[u8; 16]) -> Self {
        Self { rounds, key: *key, state: Self::initial(key), buffer: [0; 8], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn rounds(&self) -> SipHashRounds {
        self.rounds
    }

    pub fn key(&self) -> [u8; 16] {
        self.key
    }

    /// Folds the key into the four starting words.
    pub fn initial(key: &[u8; 16]) -> [u64; 4] {
        let low = u64::from_le_bytes([key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]]);
        let high = u64::from_le_bytes([key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15]]);
        [Self::INITIAL[0] ^ low, Self::INITIAL[1] ^ high, Self::INITIAL[2] ^ low, Self::INITIAL[3] ^ high]
    }

    pub fn permute(state: &mut [u64; 4], rounds: u8) {
        for _ in 0..rounds {
            state[0] = state[0].wrapping_add(state[1]);
            state[1] = state[1].rotate_left(13) ^ state[0];
            state[0] = state[0].rotate_left(32);
            state[2] = state[2].wrapping_add(state[3]);
            state[3] = state[3].rotate_left(16) ^ state[2];
            state[0] = state[0].wrapping_add(state[3]);
            state[3] = state[3].rotate_left(21) ^ state[0];
            state[2] = state[2].wrapping_add(state[1]);
            state[1] = state[1].rotate_left(17) ^ state[2];
            state[2] = state[2].rotate_left(32);
        }
    }

    /// Folds one eight byte word into the state.
    pub fn fold(state: &mut [u64; 4], word: u64, rounds: u8) {
        state[3] ^= word;
        Self::permute(state, rounds);
        state[0] ^= word;
    }

    pub fn absorb(state: &mut [u64; 4], buffer: &mut [u8; 8], length: &mut u64, rounds: SipHashRounds, data: &[u8]) {
        let mut filled = (*length % Self::BLOCK_SIZE as u64) as usize;
        let mut offset = 0;
        *length = length.wrapping_add(data.len() as u64);
        if filled != 0 {
            offset = (Self::BLOCK_SIZE - filled).min(data.len());
            buffer[filled..filled + offset].copy_from_slice(&data[..offset]);
            filled += offset;
            if filled < Self::BLOCK_SIZE {
                return;
            }
            Self::fold(state, u64::from_le_bytes(*buffer), rounds.compression);
        }
        let mut data = &data[offset..];
        while let Some((block, rest)) = data.split_first_chunk::<{ Self::BLOCK_SIZE }>() {
            Self::fold(state, u64::from_le_bytes(*block), rounds.compression);
            data = rest;
        }
        buffer[..data.len()].copy_from_slice(data);
    }

    pub fn squeeze(state: &[u64; 4], buffer: &[u8; 8], length: u64, rounds: SipHashRounds) -> u64 {
        let mut state = *state;
        let filled = (length % Self::BLOCK_SIZE as u64) as usize;
        let mut block = [0; Self::BLOCK_SIZE];
        block[..filled].copy_from_slice(&buffer[..filled]);
        block[Self::BLOCK_SIZE - 1] = (length & 0xFF) as u8;
        Self::fold(&mut state, u64::from_le_bytes(block), rounds.compression);
        state[2] ^= 0xFF;
        Self::permute(&mut state, rounds.finalization);
        state[0] ^ state[1] ^ state[2] ^ state[3]
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Self::absorb(&mut self.state, &mut self.buffer, &mut self.length, self.rounds, data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> u64 {
        match &self.backend {
            ProviderBackend::Builtin => Self::squeeze(&self.state, &self.buffer, self.length, self.rounds),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; Self::DIGEST_SIZE];
                provider.finalize(*handle, &mut digest);
                u64::from_be_bytes(digest)
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => (self.state, self.buffer, self.length) = (Self::initial(&self.key), [0; 8], 0),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(rounds: SipHashRounds, key: &[u8; 16], data: &[u8]) -> u64 {
        let mut digest = [0; Self::DIGEST_SIZE];
        match rounds.name().and_then(|name| HashProviders::digest(&HashProviderRequest::new(name).with_key(key), data, &mut digest)) {
            Some(_) => u64::from_be_bytes(digest),
            None => {
                let mut hash = Self::builtin(rounds, key);
                hash.update(data);
                hash.finalize()
            }
        }
    }
}

impl Clone for SipHash {
    fn clone(&self) -> Self {
        Self { rounds: self.rounds, key: self.key, state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}
