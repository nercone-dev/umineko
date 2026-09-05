use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug)]
pub struct XXH64 {
    state: [u64; 4],
    buffer: [u8; 32],
    length: u64,
    seed: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl XXH64 {
    pub const NAME: &'static str = "XXH64";
    pub const DIGEST_SIZE: usize = 8;
    pub const BLOCK_SIZE: usize = 32;
    pub const PRIMES: [u64; 5] = [
        0x9E37_79B1_85EB_CA87,
        0xC2B2_AE3D_27D4_EB4F,
        0x1656_67B1_9E37_79F9,
        0x85EB_CA77_C2B2_AE63,
        0x27D4_EB2F_1656_67C5,
    ];

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(0),
            backend => Self { state: [0; 4], buffer: [0; 32], length: 0, seed: 0, backend },
        }
    }

    pub fn builtin(seed: u64) -> Self {
        Self { state: Self::initial(seed), buffer: [0; 32], length: 0, seed, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn with_seed(seed: u64) -> Self {
        match HashProviders::backend(&Self::request().with_seed(seed)) {
            ProviderBackend::Builtin => Self::builtin(seed),
            backend => Self { state: [0; 4], buffer: [0; 32], length: 0, seed, backend },
        }
    }

    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// The four lanes a seed starts at.
    pub fn initial(seed: u64) -> [u64; 4] {
        [
            seed.wrapping_add(Self::PRIMES[0]).wrapping_add(Self::PRIMES[1]),
            seed.wrapping_add(Self::PRIMES[1]),
            seed,
            seed.wrapping_sub(Self::PRIMES[0]),
        ]
    }

    /// Folds one word into one lane.
    pub fn round(lane: u64, word: u64) -> u64 {
        lane.wrapping_add(word.wrapping_mul(Self::PRIMES[1])).rotate_left(31).wrapping_mul(Self::PRIMES[0])
    }

    /// Folds one finished lane into the digest.
    pub fn merge(value: u64, lane: u64) -> u64 {
        (value ^ Self::round(0, lane)).wrapping_mul(Self::PRIMES[0]).wrapping_add(Self::PRIMES[3])
    }

    /// The final mixing every xxHash64 digest ends with.
    pub fn avalanche(value: u64) -> u64 {
        let value = (value ^ (value >> 33)).wrapping_mul(Self::PRIMES[1]);
        let value = (value ^ (value >> 29)).wrapping_mul(Self::PRIMES[2]);
        value ^ (value >> 32)
    }

    pub fn compress(state: &mut [u64; 4], block: &[u8; 32]) {
        for (lane, chunk) in state.iter_mut().zip(block.chunks_exact(8)) {
            *lane = Self::round(*lane, u64::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7]]));
        }
    }

    pub fn absorb(state: &mut [u64; 4], buffer: &mut [u8; 32], length: &mut u64, data: &[u8]) {
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
            Self::compress(state, buffer);
        }
        let mut data = &data[offset..];
        while let Some((block, rest)) = data.split_first_chunk::<{ Self::BLOCK_SIZE }>() {
            Self::compress(state, block);
            data = rest;
        }
        buffer[..data.len()].copy_from_slice(data);
    }

    pub fn squeeze(state: &[u64; 4], buffer: &[u8; 32], length: u64, seed: u64) -> u64 {
        let mut value = match length >= Self::BLOCK_SIZE as u64 {
            true => {
                let folded = state[0].rotate_left(1).wrapping_add(state[1].rotate_left(7)).wrapping_add(state[2].rotate_left(12)).wrapping_add(state[3].rotate_left(18));
                state.iter().fold(folded, |value, lane| Self::merge(value, *lane))
            }
            false => seed.wrapping_add(Self::PRIMES[4]),
        };
        let filled = (length % Self::BLOCK_SIZE as u64) as usize;
        value = value.wrapping_add(length);
        for chunk in buffer[..filled].chunks_exact(8) {
            let word = u64::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7]]);
            value = (value ^ Self::round(0, word)).rotate_left(27).wrapping_mul(Self::PRIMES[0]).wrapping_add(Self::PRIMES[3]);
        }
        let filled8 = filled / 8 * 8;
        for chunk in buffer[filled8..filled].chunks_exact(4) {
            let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as u64;
            value = (value ^ word.wrapping_mul(Self::PRIMES[0])).rotate_left(23).wrapping_mul(Self::PRIMES[1]).wrapping_add(Self::PRIMES[2]);
        }
        for byte in &buffer[filled8 + (filled - filled8) / 4 * 4..filled] {
            value = (value ^ (*byte as u64).wrapping_mul(Self::PRIMES[4])).rotate_left(11).wrapping_mul(Self::PRIMES[0]);
        }
        Self::avalanche(value)
    }

    /// The whole hash of `data` under `seed`, without a running state.
    pub fn hash(data: &[u8], seed: u64) -> u64 {
        let mut state = Self::initial(seed);
        let mut buffer = [0; Self::BLOCK_SIZE];
        let mut length = 0;
        Self::absorb(&mut state, &mut buffer, &mut length, data);
        Self::squeeze(&state, &buffer, length, seed)
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Self::absorb(&mut self.state, &mut self.buffer, &mut self.length, data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> [u8; 8] {
        match &self.backend {
            ProviderBackend::Builtin => Self::squeeze(&self.state, &self.buffer, self.length, self.seed).to_be_bytes(),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 8];
                provider.finalize(*handle, &mut digest);
                digest
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => (self.state, self.buffer, self.length) = (Self::initial(self.seed), [0; 32], 0),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8]) -> [u8; 8] {
        let mut digest = [0; 8];
        match HashProviders::digest(&Self::request(), data, &mut digest) {
            Some(_) => digest,
            None => Self::hash(data, 0).to_be_bytes(),
        }
    }
}

impl Clone for XXH64 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, seed: self.seed, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for XXH64 {
    fn default() -> Self {
        Self::new()
    }
}
