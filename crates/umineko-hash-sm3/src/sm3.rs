use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug)]
pub struct SM3 {
    state: [u32; 8],
    buffer: [u8; 64],
    length: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SM3 {
    pub const NAME: &'static str = "SM3";
    pub const DIGEST_SIZE: usize = 32;
    pub const BLOCK_SIZE: usize = 64;
    pub const ROUNDS: usize = 64;
    pub const INITIAL: [u32; 8] = [0x7380_166F, 0x4914_B2B9, 0x1724_42D7, 0xDA8A_0600, 0xA96F_30BC, 0x1631_38AA, 0xE38D_EE4D, 0xB0FB_0E4E];
    pub const ADDITIONS: [u32; 2] = [0x79CC_4519, 0x7A87_9D8A];

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { state: [0; 8], buffer: [0; 64], length: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { state: Self::INITIAL, buffer: [0; 64], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    /// The boolean function the first half of the state mixes with.
    pub fn boolean(index: usize, x: u32, y: u32, z: u32) -> u32 {
        match index < 16 {
            true => x ^ y ^ z,
            false => (x & y) | (x & z) | (y & z),
        }
    }

    /// The boolean function the second half of the state mixes with.
    pub fn boolean_parallel(index: usize, x: u32, y: u32, z: u32) -> u32 {
        match index < 16 {
            true => x ^ y ^ z,
            false => (x & y) | (!x & z),
        }
    }

    /// The permutation applied to the state word.
    pub fn permute(value: u32) -> u32 {
        value ^ value.rotate_left(9) ^ value.rotate_left(17)
    }

    /// The permutation applied while expanding the message.
    pub fn permute_expansion(value: u32) -> u32 {
        value ^ value.rotate_left(15) ^ value.rotate_left(23)
    }

    /// Expands a block into the sixty-eight message words.
    pub fn expand(block: &[u8; 64]) -> [u32; 68] {
        let mut words = [0u32; 68];
        for (word, chunk) in words.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        for index in 16..68 {
            let mixed = words[index - 16] ^ words[index - 9] ^ words[index - 3].rotate_left(15);
            words[index] = Self::permute_expansion(mixed) ^ words[index - 13].rotate_left(7) ^ words[index - 6];
        }
        words
    }

    pub fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        let words = Self::expand(block);
        let mut working = *state;
        for index in 0..Self::ROUNDS {
            let [a, b, c, d, e, f, g, h] = working;
            let addition = Self::ADDITIONS[usize::from(index >= 16)].rotate_left(index as u32 % 32);
            let sum1 = a.rotate_left(12).wrapping_add(e).wrapping_add(addition).rotate_left(7);
            let sum2 = sum1 ^ a.rotate_left(12);
            let first = Self::boolean(index, a, b, c).wrapping_add(d).wrapping_add(sum2).wrapping_add(words[index] ^ words[index + 4]);
            let second = Self::boolean_parallel(index, e, f, g).wrapping_add(h).wrapping_add(sum1).wrapping_add(words[index]);
            working = [first, a, b.rotate_left(9), c, Self::permute(second), e, f.rotate_left(19), g];
        }
        for (value, working) in state.iter_mut().zip(working) {
            *value ^= working;
        }
    }

    pub fn absorb(state: &mut [u32; 8], buffer: &mut [u8; 64], length: &mut u64, data: &[u8]) {
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

    pub fn squeeze(state: &[u32; 8], buffer: &[u8; 64], length: u64) -> [u8; 32] {
        let mut state = *state;
        let filled = (length % Self::BLOCK_SIZE as u64) as usize;
        let mut block = [0; Self::BLOCK_SIZE];
        block[..filled].copy_from_slice(&buffer[..filled]);
        block[filled] = 0x80;
        if filled + 9 > Self::BLOCK_SIZE {
            Self::compress(&mut state, &block);
            block = [0; Self::BLOCK_SIZE];
        }
        block[Self::BLOCK_SIZE - 8..].copy_from_slice(&length.wrapping_mul(8).to_be_bytes());
        Self::compress(&mut state, &block);
        let mut digest = [0; Self::DIGEST_SIZE];
        for (chunk, value) in digest.chunks_exact_mut(4).zip(state) {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        digest
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Self::absorb(&mut self.state, &mut self.buffer, &mut self.length, data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> [u8; 32] {
        match &self.backend {
            ProviderBackend::Builtin => Self::squeeze(&self.state, &self.buffer, self.length),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 32];
                provider.finalize(*handle, &mut digest);
                digest
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => (self.state, self.buffer, self.length) = (Self::INITIAL, [0; 64], 0),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut digest = [0; 32];
        match HashProviders::digest(&Self::request(), data, &mut digest) {
            Some(_) => digest,
            None => {
                let mut hash = Self::builtin();
                hash.update(data);
                hash.finalize()
            }
        }
    }
}

impl Clone for SM3 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SM3 {
    fn default() -> Self {
        Self::new()
    }
}
