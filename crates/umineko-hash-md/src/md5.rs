use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug)]
pub struct MD5 {
    state: [u32; 4],
    buffer: [u8; 64],
    length: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl MD5 {
    pub const NAME: &'static str = "MD5";
    pub const DIGEST_SIZE: usize = 16;
    pub const BLOCK_SIZE: usize = 64;
    pub const INITIAL: [u32; 4] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476];
    pub const ROTATIONS: [u32; 16] = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
    pub const ADDITIONS: [u32; 64] = [
        0xD76A_A478, 0xE8C7_B756, 0x2420_70DB, 0xC1BD_CEEE, 0xF57C_0FAF, 0x4787_C62A, 0xA830_4613, 0xFD46_9501,
        0x6980_98D8, 0x8B44_F7AF, 0xFFFF_5BB1, 0x895C_D7BE, 0x6B90_1122, 0xFD98_7193, 0xA679_438E, 0x49B4_0821,
        0xF61E_2562, 0xC040_B340, 0x265E_5A51, 0xE9B6_C7AA, 0xD62F_105D, 0x0244_1453, 0xD8A1_E681, 0xE7D3_FBC8,
        0x21E1_CDE6, 0xC337_07D6, 0xF4D5_0D87, 0x455A_14ED, 0xA9E3_E905, 0xFCEF_A3F8, 0x676F_02D9, 0x8D2A_4C8A,
        0xFFFA_3942, 0x8771_F681, 0x6D9D_6122, 0xFDE5_380C, 0xA4BE_EA44, 0x4BDE_CFA9, 0xF6BB_4B60, 0xBEBF_BC70,
        0x289B_7EC6, 0xEAA1_27FA, 0xD4EF_3085, 0x0488_1D05, 0xD9D4_D039, 0xE6DB_99E5, 0x1FA2_7CF8, 0xC4AC_5665,
        0xF429_2244, 0x432A_FF97, 0xAB94_23A7, 0xFC93_A039, 0x655B_59C3, 0x8F0C_CC92, 0xFFEF_F47D, 0x8584_5DD1,
        0x6FA8_7E4F, 0xFE2C_E6E0, 0xA301_4314, 0x4E08_11A1, 0xF753_7E82, 0xBD3A_F235, 0x2AD7_D2BB, 0xEB86_D391,
    ];

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
            1 => ((d & b) | (!d & c), (5 * index + 1) % 16),
            2 => (b ^ c ^ d, (3 * index + 5) % 16),
            _ => (c ^ (b | !d), (7 * index) % 16),
        }
    }

    pub fn compress(state: &mut [u32; 4], block: &[u8; 64]) {
        let mut words = [0u32; 16];
        for (word, chunk) in words.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let mut working = *state;
        for index in 0..64 {
            let (mixed, word) = Self::round(index, working);
            let rotation = Self::ROTATIONS[index / 16 * 4 + index % 4];
            let sum = working[0].wrapping_add(mixed).wrapping_add(Self::ADDITIONS[index]).wrapping_add(words[word]);
            working = [working[3], working[1].wrapping_add(sum.rotate_left(rotation)), working[1], working[2]];
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

impl Clone for MD5 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for MD5 {
    fn default() -> Self {
        Self::new()
    }
}
