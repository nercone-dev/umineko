use core::fmt;

use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BLAKE2 {
    S,
    B,
}

impl BLAKE2 {
    /// The message word each mixing step reads, for the twelve rounds either width runs.
    pub const SCHEDULE: [[usize; 16]; 12] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    ];
    /// The four words each mixing step touches, in column order then diagonal order.
    pub const LANES: [[usize; 4]; 8] = [
        [0, 4, 8, 12],
        [1, 5, 9, 13],
        [2, 6, 10, 14],
        [3, 7, 11, 15],
        [0, 5, 10, 15],
        [1, 6, 11, 12],
        [2, 7, 8, 13],
        [3, 4, 9, 14],
    ];

    pub fn digest_size(&self) -> usize {
        match self {
            Self::S => 32,
            Self::B => 64,
        }
    }

    pub fn block_size(&self) -> usize {
        match self {
            Self::S => 64,
            Self::B => 128,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::S => "BLAKE2s",
            Self::B => "BLAKE2b",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "BLAKE2s" => Some(Self::S),
            "BLAKE2b" => Some(Self::B),
            _ => None,
        }
    }
}

impl fmt::Display for BLAKE2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct BLAKE2S {
    state: [u32; 8],
    buffer: [u8; 64],
    length: u64,
    digest_size: usize,
    key: [u8; 32],
    key_size: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl BLAKE2S {
    pub const NAME: &'static str = "BLAKE2s";
    pub const BLOCK_SIZE: usize = 64;
    pub const DIGEST_SIZE: usize = 32;
    pub const KEY_SIZE: usize = 32;
    pub const ROUNDS: usize = 10;
    pub const INITIAL: [u32; 8] = [0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A, 0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19];
    pub const ROTATIONS: [u32; 4] = [16, 12, 8, 7];

    pub fn new(digest_size: usize) -> Self {
        match HashProviders::backend(&Self::request(digest_size)) {
            ProviderBackend::Builtin => Self::builtin(digest_size, &[]),
            backend => Self { state: [0; 8], buffer: [0; 64], length: 0, digest_size, key: [0; 32], key_size: 0, backend },
        }
    }

    pub fn with_key(digest_size: usize, key: &[u8]) -> Self {
        match HashProviders::backend(&Self::request(digest_size).with_key(key)) {
            ProviderBackend::Builtin => Self::builtin(digest_size, key),
            backend => {
                let mut stored = [0; 32];
                stored[..key.len()].copy_from_slice(key);
                Self { state: [0; 8], buffer: [0; 64], length: 0, digest_size, key: stored, key_size: key.len(), backend }
            }
        }
    }

    /// Builds a state that never consults a provider; the key may be up to `KEY_SIZE` bytes.
    pub fn builtin(digest_size: usize, key: &[u8]) -> Self {
        let digest_size = digest_size.clamp(1, Self::DIGEST_SIZE);
        let mut stored = [0; 32];
        stored[..key.len().min(Self::KEY_SIZE)].copy_from_slice(&key[..key.len().min(Self::KEY_SIZE)]);
        let mut hash = Self {
            state: Self::initial(digest_size, key.len().min(Self::KEY_SIZE)),
            buffer: [0; 64],
            length: 0,
            digest_size,
            key: stored,
            key_size: key.len().min(Self::KEY_SIZE),
            backend: ProviderBackend::Builtin,
        };
        hash.reset();
        hash
    }

    pub fn request<'a>(digest_size: usize) -> HashProviderRequest<'a> {
        HashProviderRequest::new(Self::NAME).with_digest_size(digest_size)
    }

    pub fn digest_size(&self) -> usize {
        self.digest_size
    }

    /// The eight words a digest size and key size start the state at.
    pub fn initial(digest_size: usize, key_size: usize) -> [u32; 8] {
        let mut state = Self::INITIAL;
        state[0] ^= 0x0101_0000 ^ ((key_size as u32) << 8) ^ digest_size as u32;
        state
    }

    /// The number of bytes a running state of `length` bytes still holds unmixed.
    pub fn filled(length: u64) -> usize {
        match length {
            0 => 0,
            length => ((length - 1) % Self::BLOCK_SIZE as u64) as usize + 1,
        }
    }

    pub fn compress(state: &mut [u32; 8], block: &[u8; 64], counter: u64, last: bool) {
        let mut words = [0u32; 16];
        for (word, chunk) in words.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let mut working = [0u32; 16];
        working[..8].copy_from_slice(state);
        working[8..].copy_from_slice(&Self::INITIAL);
        working[12] ^= counter as u32;
        working[13] ^= (counter >> 32) as u32;
        if last {
            working[14] = !working[14];
        }
        for round in 0..Self::ROUNDS {
            let schedule = BLAKE2::SCHEDULE[round];
            for (step, lanes) in BLAKE2::LANES.iter().enumerate() {
                Self::mix(&mut working, *lanes, words[schedule[step * 2]], words[schedule[step * 2 + 1]]);
            }
        }
        for (index, value) in state.iter_mut().enumerate() {
            *value ^= working[index] ^ working[index + 8];
        }
    }

    /// The mixing step, over the four words `lanes` names.
    pub fn mix(working: &mut [u32; 16], lanes: [usize; 4], first: u32, second: u32) {
        let [a, b, c, d] = lanes;
        working[a] = working[a].wrapping_add(working[b]).wrapping_add(first);
        working[d] = (working[d] ^ working[a]).rotate_right(Self::ROTATIONS[0]);
        working[c] = working[c].wrapping_add(working[d]);
        working[b] = (working[b] ^ working[c]).rotate_right(Self::ROTATIONS[1]);
        working[a] = working[a].wrapping_add(working[b]).wrapping_add(second);
        working[d] = (working[d] ^ working[a]).rotate_right(Self::ROTATIONS[2]);
        working[c] = working[c].wrapping_add(working[d]);
        working[b] = (working[b] ^ working[c]).rotate_right(Self::ROTATIONS[3]);
    }

    pub fn absorb(state: &mut [u32; 8], buffer: &mut [u8; 64], length: &mut u64, data: &[u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let mut filled = Self::filled(*length);
            if filled == Self::BLOCK_SIZE {
                Self::compress(state, buffer, *length, false);
                filled = 0;
            }
            let taken = (Self::BLOCK_SIZE - filled).min(data.len() - offset);
            buffer[filled..filled + taken].copy_from_slice(&data[offset..offset + taken]);
            *length += taken as u64;
            offset += taken;
        }
    }

    pub fn squeeze(state: &[u32; 8], buffer: &[u8; 64], length: u64, digest: &mut [u8]) {
        let mut state = *state;
        let filled = Self::filled(length);
        let mut block = [0; Self::BLOCK_SIZE];
        block[..filled].copy_from_slice(&buffer[..filled]);
        Self::compress(&mut state, &block, length, true);
        let mut output = [0; Self::DIGEST_SIZE];
        for (chunk, value) in output.chunks_exact_mut(4).zip(state) {
            chunk.copy_from_slice(&value.to_le_bytes());
        }
        let taken = digest.len().min(Self::DIGEST_SIZE);
        digest[..taken].copy_from_slice(&output[..taken]);
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Self::absorb(&mut self.state, &mut self.buffer, &mut self.length, data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self, digest: &mut [u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Self::squeeze(&self.state, &self.buffer, self.length, digest),
            ProviderBackend::Handle { provider, handle } => {
                provider.finalize(*handle, digest);
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => {
                (self.state, self.buffer, self.length) = (Self::initial(self.digest_size, self.key_size), [0; 64], 0);
                if self.key_size != 0 {
                    let mut block = [0; Self::BLOCK_SIZE];
                    block[..self.key_size].copy_from_slice(&self.key[..self.key_size]);
                    Self::absorb(&mut self.state, &mut self.buffer, &mut self.length, &block);
                }
            }
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8], digest: &mut [u8]) {
        match HashProviders::digest(&Self::request(digest.len()), data, digest) {
            Some(_) => {}
            None => {
                let mut hash = Self::builtin(digest.len(), &[]);
                hash.update(data);
                hash.finalize(digest);
            }
        }
    }
}

impl Clone for BLAKE2S {
    fn clone(&self) -> Self {
        Self {
            state: self.state,
            buffer: self.buffer,
            length: self.length,
            digest_size: self.digest_size,
            key: self.key,
            key_size: self.key_size,
            backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)),
        }
    }
}

#[derive(Debug)]
pub struct BLAKE2B {
    state: [u64; 8],
    buffer: [u8; 128],
    length: u64,
    digest_size: usize,
    key: [u8; 64],
    key_size: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl BLAKE2B {
    pub const NAME: &'static str = "BLAKE2b";
    pub const BLOCK_SIZE: usize = 128;
    pub const DIGEST_SIZE: usize = 64;
    pub const KEY_SIZE: usize = 64;
    pub const ROUNDS: usize = 12;
    pub const INITIAL: [u64; 8] = [
        0x6A09_E667_F3BC_C908,
        0xBB67_AE85_84CA_A73B,
        0x3C6E_F372_FE94_F82B,
        0xA54F_F53A_5F1D_36F1,
        0x510E_527F_ADE6_82D1,
        0x9B05_688C_2B3E_6C1F,
        0x1F83_D9AB_FB41_BD6B,
        0x5BE0_CD19_137E_2179,
    ];
    pub const ROTATIONS: [u32; 4] = [32, 24, 16, 63];

    pub fn new(digest_size: usize) -> Self {
        match HashProviders::backend(&Self::request(digest_size)) {
            ProviderBackend::Builtin => Self::builtin(digest_size, &[]),
            backend => Self { state: [0; 8], buffer: [0; 128], length: 0, digest_size, key: [0; 64], key_size: 0, backend },
        }
    }

    pub fn with_key(digest_size: usize, key: &[u8]) -> Self {
        match HashProviders::backend(&Self::request(digest_size).with_key(key)) {
            ProviderBackend::Builtin => Self::builtin(digest_size, key),
            backend => {
                let mut stored = [0; 64];
                stored[..key.len()].copy_from_slice(key);
                Self { state: [0; 8], buffer: [0; 128], length: 0, digest_size, key: stored, key_size: key.len(), backend }
            }
        }
    }

    /// Builds a state that never consults a provider; the key may be up to `KEY_SIZE` bytes.
    pub fn builtin(digest_size: usize, key: &[u8]) -> Self {
        let digest_size = digest_size.clamp(1, Self::DIGEST_SIZE);
        let mut stored = [0; 64];
        stored[..key.len().min(Self::KEY_SIZE)].copy_from_slice(&key[..key.len().min(Self::KEY_SIZE)]);
        let mut hash = Self {
            state: Self::initial(digest_size, key.len().min(Self::KEY_SIZE)),
            buffer: [0; 128],
            length: 0,
            digest_size,
            key: stored,
            key_size: key.len().min(Self::KEY_SIZE),
            backend: ProviderBackend::Builtin,
        };
        hash.reset();
        hash
    }

    pub fn request<'a>(digest_size: usize) -> HashProviderRequest<'a> {
        HashProviderRequest::new(Self::NAME).with_digest_size(digest_size)
    }

    pub fn digest_size(&self) -> usize {
        self.digest_size
    }

    /// The eight words a digest size and key size start the state at.
    pub fn initial(digest_size: usize, key_size: usize) -> [u64; 8] {
        let mut state = Self::INITIAL;
        state[0] ^= 0x0101_0000 ^ ((key_size as u64) << 8) ^ digest_size as u64;
        state
    }

    /// The number of bytes a running state of `length` bytes still holds unmixed.
    pub fn filled(length: u64) -> usize {
        match length {
            0 => 0,
            length => ((length - 1) % Self::BLOCK_SIZE as u64) as usize + 1,
        }
    }

    pub fn compress(state: &mut [u64; 8], block: &[u8; 128], counter: u64, last: bool) {
        let mut words = [0u64; 16];
        for (word, chunk) in words.iter_mut().zip(block.chunks_exact(8)) {
            *word = u64::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7]]);
        }
        let mut working = [0u64; 16];
        working[..8].copy_from_slice(state);
        working[8..].copy_from_slice(&Self::INITIAL);
        working[12] ^= counter;
        if last {
            working[14] = !working[14];
        }
        for round in 0..Self::ROUNDS {
            let schedule = BLAKE2::SCHEDULE[round];
            for (step, lanes) in BLAKE2::LANES.iter().enumerate() {
                Self::mix(&mut working, *lanes, words[schedule[step * 2]], words[schedule[step * 2 + 1]]);
            }
        }
        for (index, value) in state.iter_mut().enumerate() {
            *value ^= working[index] ^ working[index + 8];
        }
    }

    /// The mixing step, over the four words `lanes` names.
    pub fn mix(working: &mut [u64; 16], lanes: [usize; 4], first: u64, second: u64) {
        let [a, b, c, d] = lanes;
        working[a] = working[a].wrapping_add(working[b]).wrapping_add(first);
        working[d] = (working[d] ^ working[a]).rotate_right(Self::ROTATIONS[0]);
        working[c] = working[c].wrapping_add(working[d]);
        working[b] = (working[b] ^ working[c]).rotate_right(Self::ROTATIONS[1]);
        working[a] = working[a].wrapping_add(working[b]).wrapping_add(second);
        working[d] = (working[d] ^ working[a]).rotate_right(Self::ROTATIONS[2]);
        working[c] = working[c].wrapping_add(working[d]);
        working[b] = (working[b] ^ working[c]).rotate_right(Self::ROTATIONS[3]);
    }

    pub fn absorb(state: &mut [u64; 8], buffer: &mut [u8; 128], length: &mut u64, data: &[u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let mut filled = Self::filled(*length);
            if filled == Self::BLOCK_SIZE {
                Self::compress(state, buffer, *length, false);
                filled = 0;
            }
            let taken = (Self::BLOCK_SIZE - filled).min(data.len() - offset);
            buffer[filled..filled + taken].copy_from_slice(&data[offset..offset + taken]);
            *length += taken as u64;
            offset += taken;
        }
    }

    pub fn squeeze(state: &[u64; 8], buffer: &[u8; 128], length: u64, digest: &mut [u8]) {
        let mut state = *state;
        let filled = Self::filled(length);
        let mut block = [0; Self::BLOCK_SIZE];
        block[..filled].copy_from_slice(&buffer[..filled]);
        Self::compress(&mut state, &block, length, true);
        let mut output = [0; Self::DIGEST_SIZE];
        for (chunk, value) in output.chunks_exact_mut(8).zip(state) {
            chunk.copy_from_slice(&value.to_le_bytes());
        }
        let taken = digest.len().min(Self::DIGEST_SIZE);
        digest[..taken].copy_from_slice(&output[..taken]);
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Self::absorb(&mut self.state, &mut self.buffer, &mut self.length, data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self, digest: &mut [u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Self::squeeze(&self.state, &self.buffer, self.length, digest),
            ProviderBackend::Handle { provider, handle } => {
                provider.finalize(*handle, digest);
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => {
                (self.state, self.buffer, self.length) = (Self::initial(self.digest_size, self.key_size), [0; 128], 0);
                if self.key_size != 0 {
                    let mut block = [0; Self::BLOCK_SIZE];
                    block[..self.key_size].copy_from_slice(&self.key[..self.key_size]);
                    Self::absorb(&mut self.state, &mut self.buffer, &mut self.length, &block);
                }
            }
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8], digest: &mut [u8]) {
        match HashProviders::digest(&Self::request(digest.len()), data, digest) {
            Some(_) => {}
            None => {
                let mut hash = Self::builtin(digest.len(), &[]);
                hash.update(data);
                hash.finalize(digest);
            }
        }
    }
}

impl Clone for BLAKE2B {
    fn clone(&self) -> Self {
        Self {
            state: self.state,
            buffer: self.buffer,
            length: self.length,
            digest_size: self.digest_size,
            key: self.key,
            key_size: self.key_size,
            backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)),
        }
    }
}
