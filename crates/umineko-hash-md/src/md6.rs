use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MD6Parameters {
    pub digest_size: usize,
    pub rounds: usize,
    pub mode: u8,
    pub key: [u8; 64],
    pub key_size: usize,
}

impl MD6Parameters {
    pub const KEY_SIZE: usize = 64;
    pub const DIGEST_SIZE: usize = 64;
    /// The tree height at which the mode falls back to a sequential chain.
    pub const MODE: u8 = 64;
    pub const WORDS: usize = 89;
    pub const BLOCK_WORDS: usize = 64;
    pub const CHAINING_WORDS: usize = 16;
    /// The taps the recurrence reads, counted back from the word it writes.
    pub const TAPS: [usize; 5] = [17, 18, 21, 31, 67];
    pub const SHIFTS_RIGHT: [u32; 16] = [10, 5, 13, 10, 11, 12, 2, 7, 14, 15, 7, 13, 11, 7, 6, 12];
    pub const SHIFTS_LEFT: [u32; 16] = [11, 24, 9, 16, 15, 9, 27, 15, 6, 2, 29, 8, 15, 5, 31, 9];
    /// The fractional part of the square root of six.
    pub const Q: [u64; 15] = [
        0x7311_C281_2425_CFA0,
        0x6432_2864_34AA_C8E7,
        0xB604_50E9_EF68_B7C1,
        0xE8FB_2390_8D9F_06F1,
        0xDD2E_76CB_A691_E5BF,
        0x0CD0_D63B_2C30_BC41,
        0x1F8C_CF68_2305_8F8A,
        0x54E5_ED5B_88E3_775D,
        0x4AD1_2AAE_0A6D_6031,
        0x3E7F_16BB_8822_2E0D,
        0x8AF8_671D_3FB5_0C2C,
        0x995A_D117_8BD2_5C31,
        0xC878_C1DD_04C4_B633,
        0x3B72_066C_7A15_52AC,
        0x0D6F_3522_631E_FFCB,
    ];
    pub const ROUND_INITIAL: u64 = 0x0123_4567_89AB_CDEF;
    pub const ROUND_MASK: u64 = 0x7311_C281_2425_CFA0;

    pub fn new(digest_size: usize, key: &[u8]) -> Self {
        let digest_size = digest_size.clamp(1, Self::DIGEST_SIZE);
        let key_size = key.len().min(Self::KEY_SIZE);
        let mut stored = [0; Self::KEY_SIZE];
        stored[..key_size].copy_from_slice(&key[..key_size]);
        Self { digest_size, rounds: Self::rounds(digest_size, key_size), mode: Self::MODE, key: stored, key_size }
    }

    /// The number of rounds a digest size and key size ask for.
    pub fn rounds(digest_size: usize, key_size: usize) -> usize {
        let rounds = 40 + digest_size * 2;
        match key_size {
            0 => rounds,
            _ => rounds.max(80),
        }
    }

    /// The word naming the node a compression stands for.
    pub fn unique(&self, level: u8, index: u64) -> u64 {
        ((level as u64) << 56) | (index & 0x00FF_FFFF_FFFF_FFFF)
    }

    /// The word carrying the parameters a compression runs under.
    pub fn control(&self, padding: u16, last: bool) -> u64 {
        ((self.rounds as u64) << 48)
            | ((self.mode as u64) << 40)
            | ((last as u64) << 36)
            | ((padding as u64) << 20)
            | ((self.key_size as u64) << 12)
            | (self.digest_size as u64 * 8)
    }

    /// Folds one block of sixty-four words into a chaining value of sixteen.
    pub fn compress(&self, block: &[u64; 64], level: u8, index: u64, padding: u16, last: bool) -> [u64; 16] {
        let mut words = [0u64; Self::WORDS];
        words[..15].copy_from_slice(&Self::Q);
        for (word, chunk) in words[15..23].iter_mut().zip(self.key.chunks_exact(8)) {
            *word = u64::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7]]);
        }
        words[23] = self.unique(level, index);
        words[24] = self.control(padding, last);
        words[25..].copy_from_slice(block);
        let mut round = Self::ROUND_INITIAL;
        let mut position = Self::WORDS;
        for _ in 0..self.rounds {
            for step in 0..16 {
                let taps: [u64; 5] = core::array::from_fn(|tap| words[(position - Self::TAPS[tap]) % Self::WORDS]);
                let mut value = round ^ words[position % Self::WORDS] ^ taps[0];
                value ^= (taps[1] & taps[2]) ^ (taps[3] & taps[4]);
                value ^= value >> Self::SHIFTS_RIGHT[step];
                words[position % Self::WORDS] = value ^ (value << Self::SHIFTS_LEFT[step]);
                position += 1;
            }
            round = round.rotate_left(1) ^ (round & Self::ROUND_MASK);
        }
        let mut chaining = [0; Self::CHAINING_WORDS];
        for (offset, value) in chaining.iter_mut().enumerate() {
            *value = words[(position - Self::CHAINING_WORDS + offset) % Self::WORDS];
        }
        chaining
    }

    /// The sixty-four words of a block of five hundred and twelve bytes.
    pub fn words(block: &[u8; 512]) -> [u64; 64] {
        let mut words = [0; 64];
        for (word, chunk) in words.iter_mut().zip(block.chunks_exact(8)) {
            *word = u64::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7]]);
        }
        words
    }
}

#[derive(Debug)]
pub struct MD6 {
    parameters: MD6Parameters,
    buffer: [u8; 512],
    length: u64,
    stack: [[u64; 16]; MD6::LEVELS * 4],
    pending: [u8; MD6::LEVELS],
    blocks: [u64; MD6::LEVELS],
    backend: ProviderBackend<dyn HashProvider>,
}

impl MD6 {
    pub const NAME: &'static str = "MD6";
    pub const BLOCK_SIZE: usize = 512;
    pub const DIGEST_SIZE: usize = 64;
    pub const KEY_SIZE: usize = 64;
    /// The tree height the running state carries, which covers inputs of a few petabytes.
    pub const LEVELS: usize = 22;

    pub fn new(digest_size: usize) -> Self {
        match HashProviders::backend(&Self::request(digest_size)) {
            ProviderBackend::Builtin => Self::builtin(digest_size, &[]),
            backend => Self::attached(digest_size, &[], backend),
        }
    }

    pub fn with_key(digest_size: usize, key: &[u8]) -> Self {
        match HashProviders::backend(&Self::request(digest_size).with_key(key)) {
            ProviderBackend::Builtin => Self::builtin(digest_size, key),
            backend => Self::attached(digest_size, key, backend),
        }
    }

    /// Builds a state that never consults a provider; the key may be up to `KEY_SIZE` bytes.
    pub fn builtin(digest_size: usize, key: &[u8]) -> Self {
        Self::attached(digest_size, key, ProviderBackend::Builtin)
    }

    pub fn attached(digest_size: usize, key: &[u8], backend: ProviderBackend<dyn HashProvider>) -> Self {
        Self {
            parameters: MD6Parameters::new(digest_size, key),
            buffer: [0; 512],
            length: 0,
            stack: [[0; 16]; Self::LEVELS * 4],
            pending: [0; Self::LEVELS],
            blocks: [0; Self::LEVELS],
            backend,
        }
    }

    pub fn request<'a>(digest_size: usize) -> HashProviderRequest<'a> {
        HashProviderRequest::new(Self::NAME).with_digest_size(digest_size)
    }

    pub fn parameters(&self) -> &MD6Parameters {
        &self.parameters
    }

    pub fn digest_size(&self) -> usize {
        self.parameters.digest_size
    }

    /// The number of bytes a running state of `length` bytes still holds unmixed.
    pub fn filled(length: u64) -> usize {
        match length {
            0 => 0,
            length => ((length - 1) % Self::BLOCK_SIZE as u64) as usize + 1,
        }
    }

    /// Hands one finished chaining value to the level above, folding the level it fills.
    pub fn push(parameters: &MD6Parameters, stack: &mut [[u64; 16]; MD6::LEVELS * 4], pending: &mut [u8; MD6::LEVELS], blocks: &mut [u64; MD6::LEVELS], level: usize, chaining: [u64; 16]) {
        if pending[level] == 4 {
            let mut block = [0; 64];
            for (index, value) in stack[level * 4..level * 4 + 4].iter().enumerate() {
                block[index * 16..index * 16 + 16].copy_from_slice(value);
            }
            let folded = parameters.compress(&block, level as u8 + 1, blocks[level], 0, false);
            blocks[level] += 1;
            pending[level] = 0;
            Self::push(parameters, stack, pending, blocks, level + 1, folded);
        }
        stack[level * 4 + pending[level] as usize] = chaining;
        pending[level] += 1;
    }

    /// Closes every level and returns the chaining value the root produces.
    pub fn root(&self) -> [u64; 16] {
        let (mut stack, mut pending, mut blocks) = (self.stack, self.pending, self.blocks);
        let filled = Self::filled(self.length);
        let mut block = [0; Self::BLOCK_SIZE];
        block[..filled].copy_from_slice(&self.buffer[..filled]);
        let mut last = blocks[0] == 0;
        let mut chaining = self.parameters.compress(&MD6Parameters::words(&block), 1, blocks[0], ((Self::BLOCK_SIZE - filled) * 8) as u16, last);
        let mut level = 0;
        while !last {
            level += 1;
            Self::push(&self.parameters, &mut stack, &mut pending, &mut blocks, level, chaining);
            let count = pending[level] as usize;
            let mut block = [0; 64];
            for (index, value) in stack[level * 4..level * 4 + count].iter().enumerate() {
                block[index * 16..index * 16 + 16].copy_from_slice(value);
            }
            last = blocks[level] == 0;
            chaining = self.parameters.compress(&block, level as u8 + 1, blocks[level], ((4 - count) * 16 * 8 * 8) as u16, last);
        }
        chaining
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => {
                let mut offset = 0;
                while offset < data.len() {
                    let mut filled = Self::filled(self.length);
                    if filled == Self::BLOCK_SIZE {
                        let folded = self.parameters.compress(&MD6Parameters::words(&self.buffer), 1, self.blocks[0], 0, false);
                        self.blocks[0] += 1;
                        Self::push(&self.parameters, &mut self.stack, &mut self.pending, &mut self.blocks, 1, folded);
                        filled = 0;
                    }
                    let taken = (Self::BLOCK_SIZE - filled).min(data.len() - offset);
                    self.buffer[filled..filled + taken].copy_from_slice(&data[offset..offset + taken]);
                    self.length += taken as u64;
                    offset += taken;
                }
            }
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self, digest: &mut [u8]) {
        match &self.backend {
            ProviderBackend::Builtin => {
                let chaining = self.root();
                let mut output = [0; 128];
                for (chunk, value) in output.chunks_exact_mut(8).zip(chaining) {
                    chunk.copy_from_slice(&value.to_be_bytes());
                }
                let taken = digest.len().min(self.parameters.digest_size);
                digest[..taken].copy_from_slice(&output[128 - self.parameters.digest_size..128 - self.parameters.digest_size + taken]);
            }
            ProviderBackend::Handle { provider, handle } => {
                provider.finalize(*handle, digest);
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => {
                (self.buffer, self.length) = ([0; 512], 0);
                (self.stack, self.pending, self.blocks) = ([[0; 16]; Self::LEVELS * 4], [0; Self::LEVELS], [0; Self::LEVELS]);
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

impl Clone for MD6 {
    fn clone(&self) -> Self {
        Self {
            parameters: self.parameters,
            buffer: self.buffer,
            length: self.length,
            stack: self.stack,
            pending: self.pending,
            blocks: self.blocks,
            backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)),
        }
    }
}
