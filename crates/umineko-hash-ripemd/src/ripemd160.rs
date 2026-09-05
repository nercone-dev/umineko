use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug)]
pub struct RIPEMD160 {
    state: [u32; 5],
    buffer: [u8; 64],
    length: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl RIPEMD160 {
    pub const NAME: &'static str = "RIPEMD-160";
    pub const DIGEST_SIZE: usize = 20;
    pub const BLOCK_SIZE: usize = 64;
    pub const ROUNDS: usize = 80;
    pub const INITIAL: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    pub const ADDITIONS: [u32; 5] = [0x0000_0000, 0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xA953_FD4E];
    pub const ADDITIONS_PARALLEL: [u32; 5] = [0x50A2_8BE6, 0x5C4D_D124, 0x6D70_3EF3, 0x7A6D_76E9, 0x0000_0000];
    pub const SELECTION: [usize; 80] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ];
    pub const SELECTION_PARALLEL: [usize; 80] = [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ];
    pub const ROTATIONS: [u32; 80] = [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    ];
    pub const ROTATIONS_PARALLEL: [u32; 80] = [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    ];

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

    /// The round function for group `group`, over the three words it mixes.
    pub fn round(group: usize, x: u32, y: u32, z: u32) -> u32 {
        match group {
            0 => x ^ y ^ z,
            1 => (x & y) | (!x & z),
            2 => (x | !y) ^ z,
            3 => (x & z) | (y & !z),
            _ => x ^ (y | !z),
        }
    }

    /// Runs one line of eighty steps; the parallel line reads the round functions in reverse.
    pub fn line(state: [u32; 5], words: &[u32; 16], parallel: bool) -> [u32; 5] {
        let mut working = state;
        for index in 0..Self::ROUNDS {
            let group = index / 16;
            let (selection, rotation, addition, group) = match parallel {
                true => (Self::SELECTION_PARALLEL[index], Self::ROTATIONS_PARALLEL[index], Self::ADDITIONS_PARALLEL[group], 4 - group),
                false => (Self::SELECTION[index], Self::ROTATIONS[index], Self::ADDITIONS[group], group),
            };
            let mixed = Self::round(group, working[1], working[2], working[3]);
            let step = working[0]
                .wrapping_add(mixed)
                .wrapping_add(words[selection])
                .wrapping_add(addition)
                .rotate_left(rotation)
                .wrapping_add(working[4]);
            working = [working[4], step, working[1], working[2].rotate_left(10), working[3]];
        }
        working
    }

    pub fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
        let mut words = [0u32; 16];
        for (word, chunk) in words.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let left = Self::line(*state, &words, false);
        let right = Self::line(*state, &words, true);
        *state = [
            state[1].wrapping_add(left[2]).wrapping_add(right[3]),
            state[2].wrapping_add(left[3]).wrapping_add(right[4]),
            state[3].wrapping_add(left[4]).wrapping_add(right[0]),
            state[4].wrapping_add(left[0]).wrapping_add(right[1]),
            state[0].wrapping_add(left[1]).wrapping_add(right[2]),
        ];
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

impl Clone for RIPEMD160 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for RIPEMD160 {
    fn default() -> Self {
        Self::new()
    }
}
