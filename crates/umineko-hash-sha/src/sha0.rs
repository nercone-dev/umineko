use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug)]
pub struct SHA0 {
    state: [u32; 5],
    buffer: [u8; 64],
    length: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA0 {
    pub const NAME: &'static str = "SHA-0";
    pub const DIGEST_SIZE: usize = 20;
    pub const BLOCK_SIZE: usize = 64;
    pub const ROUNDS: usize = 80;
    pub const INITIAL: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    pub const ADDITIONS: [u32; 4] = [0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6];
    /// The rotation SHA-1 applies while expanding the message, and SHA-0 leaves out.
    pub const EXPANSION: u32 = 0;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { state: [0; 5], buffer: [0; 64], length: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { state: Self::INITIAL, buffer: [0; 64], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    /// The round function for step `index`, over the four words it mixes.
    pub fn round(index: usize, state: [u32; 5]) -> u32 {
        let [_, b, c, d, _] = state;
        match index / 20 {
            0 => (b & c) | (!b & d),
            2 => (b & c) | (b & d) | (c & d),
            _ => b ^ c ^ d,
        }
    }

    /// Expands a block into the sixteen message words the rounds start from.
    pub fn expand(block: &[u8; 64]) -> [u32; 16] {
        let mut words = [0u32; 16];
        for (word, chunk) in words.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        words
    }

    /// The message word of step `index`, rotating each new word by `expansion`.
    pub fn schedule(words: &mut [u32; 16], index: usize, expansion: u32) -> u32 {
        words[index % 16] = (words[(index + 13) % 16] ^ words[(index + 8) % 16] ^ words[(index + 2) % 16] ^ words[index % 16]).rotate_left(expansion);
        words[index % 16]
    }

    pub fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
        Self::mix(state, &mut Self::expand(block), Self::EXPANSION);
    }

    /// Runs the eighty rounds, naming each message word as it reaches it.
    pub fn mix(state: &mut [u32; 5], words: &mut [u32; 16], expansion: u32) {
        let mut working = *state;
        for index in 0..Self::ROUNDS {
            let word = match index < 16 {
                true => words[index],
                false => Self::schedule(words, index, expansion),
            };
            let mixed = Self::round(index, working);
            let sum = working[0]
                .rotate_left(5)
                .wrapping_add(mixed)
                .wrapping_add(working[4])
                .wrapping_add(Self::ADDITIONS[index / 20])
                .wrapping_add(word);
            working = [sum, working[0], working[1].rotate_left(30), working[2], working[3]];
        }
        for (value, working) in state.iter_mut().zip(working) {
            *value = value.wrapping_add(working);
        }
    }

    pub fn absorb(state: &mut [u32; 5], buffer: &mut [u8; 64], length: &mut u64, data: &[u8]) {
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

    pub fn squeeze(state: &[u32; 5], buffer: &[u8; 64], length: u64) -> [u8; 20] {
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

    pub fn finalize(self) -> [u8; 20] {
        match &self.backend {
            ProviderBackend::Builtin => Self::squeeze(&self.state, &self.buffer, self.length),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 20];
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

    pub fn digest(data: &[u8]) -> [u8; 20] {
        let mut digest = [0; 20];
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

impl Clone for SHA0 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA0 {
    fn default() -> Self {
        Self::new()
    }
}
