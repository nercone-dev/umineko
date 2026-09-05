use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug)]
pub struct MD4 {
    state: [u32; 4],
    buffer: [u8; 64],
    length: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl MD4 {
    pub const NAME: &'static str = "MD4";
    pub const DIGEST_SIZE: usize = 16;
    pub const BLOCK_SIZE: usize = 64;
    pub const INITIAL: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];
    pub const ROTATIONS: [u32; 12] = [3, 7, 11, 19, 3, 5, 9, 13, 3, 9, 11, 15];
    pub const ADDITIONS: [u32; 3] = [0x0000_0000, 0x5A82_7999, 0x6ED9_EBA1];

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { state: [0; 4], buffer: [0; 64], length: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { state: Self::INITIAL, buffer: [0; 64], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    /// The round function and the message word it reads, for step `index`.
    pub fn round(index: usize, state: [u32; 4]) -> (u32, usize) {
        let [_, b, c, d] = state;
        match index / 16 {
            0 => ((b & c) | (!b & d), index),
            1 => ((b & c) | (b & d) | (c & d), (index % 4) * 4 + index % 16 / 4),
            _ => (b ^ c ^ d, ((index % 16) as u8).reverse_bits() as usize >> 4),
        }
    }

    pub fn compress(state: &mut [u32; 4], block: &[u8; 64]) {
        let mut words = [0u32; 16];
        for (word, chunk) in words.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let mut working = *state;
        for index in 0..48 {
            let (mixed, word) = Self::round(index, working);
            let rotation = Self::ROTATIONS[index / 16 * 4 + index % 4];
            let sum = working[0].wrapping_add(mixed).wrapping_add(words[word]).wrapping_add(Self::ADDITIONS[index / 16]);
            working = [working[3], sum.rotate_left(rotation), working[1], working[2]];
        }
        for (value, working) in state.iter_mut().zip(working) {
            *value = value.wrapping_add(working);
        }
    }

    pub fn absorb(state: &mut [u32; 4], buffer: &mut [u8; 64], length: &mut u64, data: &[u8]) {
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

    pub fn squeeze(state: &[u32; 4], buffer: &[u8; 64], length: u64) -> [u8; 16] {
        let mut state = *state;
        let filled = (length % Self::BLOCK_SIZE as u64) as usize;
        let mut block = [0; Self::BLOCK_SIZE];
        block[..filled].copy_from_slice(&buffer[..filled]);
        block[filled] = 0x80;
        if filled + 9 > Self::BLOCK_SIZE {
            Self::compress(&mut state, &block);
            block = [0; Self::BLOCK_SIZE];
        }
        block[Self::BLOCK_SIZE - 8..].copy_from_slice(&length.wrapping_mul(8).to_le_bytes());
        Self::compress(&mut state, &block);
        let mut digest = [0; Self::DIGEST_SIZE];
        for (chunk, value) in digest.chunks_exact_mut(4).zip(state) {
            chunk.copy_from_slice(&value.to_le_bytes());
        }
        digest
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Self::absorb(&mut self.state, &mut self.buffer, &mut self.length, data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> [u8; 16] {
        match &self.backend {
            ProviderBackend::Builtin => Self::squeeze(&self.state, &self.buffer, self.length),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 16];
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

    pub fn digest(data: &[u8]) -> [u8; 16] {
        let mut digest = [0; 16];
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

impl Clone for MD4 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for MD4 {
    fn default() -> Self {
        Self::new()
    }
}
