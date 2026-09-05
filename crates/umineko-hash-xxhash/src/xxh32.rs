use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug)]
pub struct XXH32 {
    state: [u32; 4],
    buffer: [u8; 16],
    length: u64,
    seed: u32,
    backend: ProviderBackend<dyn HashProvider>,
}

impl XXH32 {
    pub const NAME: &'static str = "XXH32";
    pub const DIGEST_SIZE: usize = 4;
    pub const BLOCK_SIZE: usize = 16;
    pub const PRIMES: [u32; 5] = [0x9E37_79B1, 0x85EB_CA77, 0xC2B2_AE3D, 0x27D4_EB2F, 0x1656_67B1];

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(0),
            backend => Self { state: [0; 4], buffer: [0; 16], length: 0, seed: 0, backend },
        }
    }

    pub fn builtin(seed: u32) -> Self {
        Self { state: Self::initial(seed), buffer: [0; 16], length: 0, seed, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn with_seed(seed: u32) -> Self {
        match HashProviders::backend(&Self::request().with_seed(seed.into())) {
            ProviderBackend::Builtin => Self::builtin(seed),
            backend => Self { state: [0; 4], buffer: [0; 16], length: 0, seed, backend },
        }
    }

    pub fn seed(&self) -> u32 {
        self.seed
    }

    /// The four lanes a seed starts at.
    pub fn initial(seed: u32) -> [u32; 4] {
        [
            seed.wrapping_add(Self::PRIMES[0]).wrapping_add(Self::PRIMES[1]),
            seed.wrapping_add(Self::PRIMES[1]),
            seed,
            seed.wrapping_sub(Self::PRIMES[0]),
        ]
    }

    /// Folds one word into one lane.
    pub fn round(lane: u32, word: u32) -> u32 {
        lane.wrapping_add(word.wrapping_mul(Self::PRIMES[1])).rotate_left(13).wrapping_mul(Self::PRIMES[0])
    }

    /// The final mixing every xxHash32 digest ends with.
    pub fn avalanche(value: u32) -> u32 {
        let value = (value ^ (value >> 15)).wrapping_mul(Self::PRIMES[1]);
        let value = (value ^ (value >> 13)).wrapping_mul(Self::PRIMES[2]);
        value ^ (value >> 16)
    }

    pub fn compress(state: &mut [u32; 4], block: &[u8; 16]) {
        for (lane, chunk) in state.iter_mut().zip(block.chunks_exact(4)) {
            *lane = Self::round(*lane, u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
    }

    pub fn absorb(state: &mut [u32; 4], buffer: &mut [u8; 16], length: &mut u64, data: &[u8]) {
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

    pub fn squeeze(state: &[u32; 4], buffer: &[u8; 16], length: u64, seed: u32) -> u32 {
        let mut value = match length >= Self::BLOCK_SIZE as u64 {
            true => state[0].rotate_left(1).wrapping_add(state[1].rotate_left(7)).wrapping_add(state[2].rotate_left(12)).wrapping_add(state[3].rotate_left(18)),
            false => seed.wrapping_add(Self::PRIMES[4]),
        };
        let filled = (length % Self::BLOCK_SIZE as u64) as usize;
        value = value.wrapping_add(length as u32);
        for chunk in buffer[..filled].chunks_exact(4) {
            let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
            value = value.wrapping_add(word.wrapping_mul(Self::PRIMES[2])).rotate_left(17).wrapping_mul(Self::PRIMES[3]);
        }
        for byte in &buffer[filled / 4 * 4..filled] {
            value = value.wrapping_add((*byte as u32).wrapping_mul(Self::PRIMES[4])).rotate_left(11).wrapping_mul(Self::PRIMES[0]);
        }
        Self::avalanche(value)
    }

    /// The whole hash of `data` under `seed`, without a running state.
    pub fn hash(data: &[u8], seed: u32) -> u32 {
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

    pub fn finalize(self) -> [u8; 4] {
        match &self.backend {
            ProviderBackend::Builtin => Self::squeeze(&self.state, &self.buffer, self.length, self.seed).to_be_bytes(),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 4];
                provider.finalize(*handle, &mut digest);
                digest
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => (self.state, self.buffer, self.length) = (Self::initial(self.seed), [0; 16], 0),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8]) -> [u8; 4] {
        let mut digest = [0; 4];
        match HashProviders::digest(&Self::request(), data, &mut digest) {
            Some(_) => digest,
            None => Self::hash(data, 0).to_be_bytes(),
        }
    }
}

impl Clone for XXH32 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, seed: self.seed, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for XXH32 {
    fn default() -> Self {
        Self::new()
    }
}
