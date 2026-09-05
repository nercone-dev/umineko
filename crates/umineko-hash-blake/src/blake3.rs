use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug)]
pub struct BLAKE3 {
    key: [u32; 8],
    flags: u32,
    chunk: [u32; 8],
    stack: [[u32; 8]; 54],
    buffer: [u8; 64],
    length: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl BLAKE3 {
    pub const NAME: &'static str = "BLAKE3";
    pub const BLOCK_SIZE: usize = 64;
    pub const CHUNK_SIZE: usize = 1024;
    pub const DIGEST_SIZE: usize = 32;
    pub const KEY_SIZE: usize = 32;
    pub const ROUNDS: usize = 7;
    pub const INITIAL: [u32; 8] = [0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A, 0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19];
    pub const ROTATIONS: [u32; 4] = [16, 12, 8, 7];
    pub const PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
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
    pub const CHUNK_START: u32 = 1;
    pub const CHUNK_END: u32 = 2;
    pub const PARENT: u32 = 4;
    pub const ROOT: u32 = 8;
    pub const KEYED_HASH: u32 = 16;
    pub const DERIVE_KEY_CONTEXT: u32 = 32;
    pub const DERIVE_KEY_MATERIAL: u32 = 64;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(Self::INITIAL, 0),
            backend => Self { key: Self::INITIAL, flags: 0, chunk: [0; 8], stack: [[0; 8]; 54], buffer: [0; 64], length: 0, backend },
        }
    }

    /// Builds a state that never consults a provider, over a key and a mode.
    pub fn builtin(key: [u32; 8], flags: u32) -> Self {
        Self { key, flags, chunk: key, stack: [[0; 8]; 54], buffer: [0; 64], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn with_key(key: &[u8; 32]) -> Self {
        match HashProviders::backend(&Self::request().with_key(key)) {
            ProviderBackend::Builtin => Self::builtin(Self::words(key), Self::KEYED_HASH),
            backend => Self { key: Self::words(key), flags: Self::KEYED_HASH, chunk: [0; 8], stack: [[0; 8]; 54], buffer: [0; 64], length: 0, backend },
        }
    }

    pub fn with_context(context: &str) -> Self {
        match HashProviders::backend(&Self::request().with_customization(context.as_bytes())) {
            ProviderBackend::Builtin => Self::builtin(Self::context(context), Self::DERIVE_KEY_MATERIAL),
            backend => Self { key: Self::context(context), flags: Self::DERIVE_KEY_MATERIAL, chunk: [0; 8], stack: [[0; 8]; 54], buffer: [0; 64], length: 0, backend },
        }
    }

    /// The key a context string derives, which keys the material that follows it.
    pub fn context(context: &str) -> [u32; 8] {
        let mut hash = Self::builtin(Self::INITIAL, Self::DERIVE_KEY_CONTEXT);
        let mut derived = [0; Self::KEY_SIZE];
        hash.update(context.as_bytes());
        hash.finalize(&mut derived);
        Self::words(&derived)
    }

    /// The eight little endian words of a key.
    pub fn words(key: &[u8; 32]) -> [u32; 8] {
        let mut words = [0; 8];
        for (word, chunk) in words.iter_mut().zip(key.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        words
    }

    /// The number of bytes a running state of `length` bytes still holds unmixed.
    pub fn filled(length: u64) -> usize {
        match length {
            0 => 0,
            length => ((length - 1) % Self::BLOCK_SIZE as u64) as usize + 1,
        }
    }

    /// The number of blocks a running state of `length` bytes has already mixed.
    pub fn blocks(length: u64) -> u64 {
        (length - Self::filled(length) as u64) / Self::BLOCK_SIZE as u64
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

    /// The whole sixteen word output of the compression function.
    pub fn compress(chaining: &[u32; 8], block: &[u8; 64], counter: u64, length: u32, flags: u32) -> [u32; 16] {
        let mut words = [0u32; 16];
        for (word, chunk) in words.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let mut working = [0u32; 16];
        working[..8].copy_from_slice(chaining);
        working[8..12].copy_from_slice(&Self::INITIAL[..4]);
        working[12] = counter as u32;
        working[13] = (counter >> 32) as u32;
        working[14] = length;
        working[15] = flags;
        for round in 0..Self::ROUNDS {
            for (step, lanes) in Self::LANES.iter().enumerate() {
                Self::mix(&mut working, *lanes, words[step * 2], words[step * 2 + 1]);
            }
            if round + 1 < Self::ROUNDS {
                words = core::array::from_fn(|index| words[Self::PERMUTATION[index]]);
            }
        }
        for index in 0..8 {
            working[index] ^= working[index + 8];
            working[index + 8] ^= chaining[index];
        }
        working
    }

    /// The chaining value a compression produces.
    pub fn chaining(output: &[u32; 16]) -> [u32; 8] {
        let mut chaining = [0; 8];
        chaining.copy_from_slice(&output[..8]);
        chaining
    }

    /// The block two chaining values form when a parent node joins them.
    pub fn parent(left: &[u32; 8], right: &[u32; 8]) -> [u8; 64] {
        let mut block = [0; 64];
        for (chunk, value) in block.chunks_exact_mut(4).zip(left.iter().chain(right)) {
            chunk.copy_from_slice(&value.to_le_bytes());
        }
        block
    }

    /// Pushes a finished chunk onto the stack, joining the subtrees it completes.
    pub fn push(stack: &mut [[u32; 8]; 54], chaining: [u32; 8], chunks: u64, key: &[u32; 8], flags: u32) {
        let mut chaining = chaining;
        let mut depth = (chunks - 1).count_ones() as usize;
        let mut chunks = chunks;
        while chunks & 1 == 0 {
            depth -= 1;
            let block = Self::parent(&stack[depth], &chaining);
            chaining = Self::chaining(&Self::compress(key, &block, 0, Self::BLOCK_SIZE as u32, flags | Self::PARENT));
            chunks >>= 1;
        }
        stack[depth] = chaining;
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => {
                let mut offset = 0;
                while offset < data.len() {
                    let mut filled = Self::filled(self.length);
                    if filled == Self::BLOCK_SIZE {
                        let blocks = Self::blocks(self.length);
                        let counter = blocks / 16;
                        let index = blocks % 16;
                        let mut flags = self.flags;
                        if index == 0 {
                            flags |= Self::CHUNK_START;
                        }
                        if index == 15 {
                            flags |= Self::CHUNK_END;
                        }
                        let output = Self::compress(&self.chunk, &self.buffer, counter, Self::BLOCK_SIZE as u32, flags);
                        match index == 15 {
                            true => {
                                Self::push(&mut self.stack, Self::chaining(&output), counter + 1, &self.key, self.flags);
                                self.chunk = self.key;
                            }
                            false => self.chunk = Self::chaining(&output),
                        }
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
                let filled = Self::filled(self.length);
                let blocks = Self::blocks(self.length);
                let counter = blocks / 16;
                let index = blocks % 16;
                let mut flags = self.flags | Self::CHUNK_END;
                if index == 0 {
                    flags |= Self::CHUNK_START;
                }
                let mut block = [0; Self::BLOCK_SIZE];
                block[..filled].copy_from_slice(&self.buffer[..filled]);
                let (mut chaining, mut block, mut counter, mut length, mut flags) = (self.chunk, block, counter, filled as u32, flags);
                for depth in (0..counter.count_ones() as usize).rev() {
                    let joined = Self::chaining(&Self::compress(&chaining, &block, counter, length, flags));
                    block = Self::parent(&self.stack[depth], &joined);
                    chaining = self.key;
                    counter = 0;
                    length = Self::BLOCK_SIZE as u32;
                    flags = self.flags | Self::PARENT;
                }
                let mut offset = 0;
                while offset < digest.len() {
                    let output = Self::compress(&chaining, &block, offset as u64 / Self::BLOCK_SIZE as u64, length, flags | Self::ROOT);
                    let taken = (digest.len() - offset).min(Self::BLOCK_SIZE);
                    for (index, byte) in digest[offset..offset + taken].iter_mut().enumerate() {
                        *byte = (output[index / 4] >> (8 * (index % 4))) as u8;
                    }
                    offset += taken;
                }
            }
            ProviderBackend::Handle { provider, handle } => {
                provider.finalize(*handle, digest);
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => (self.chunk, self.stack, self.buffer, self.length) = (self.key, [[0; 8]; 54], [0; 64], 0),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8], digest: &mut [u8]) {
        match HashProviders::digest(&Self::request(), data, digest) {
            Some(_) => {}
            None => {
                let mut hash = Self::builtin(Self::INITIAL, 0);
                hash.update(data);
                hash.finalize(digest);
            }
        }
    }
}

impl Clone for BLAKE3 {
    fn clone(&self) -> Self {
        Self {
            key: self.key,
            flags: self.flags,
            chunk: self.chunk,
            stack: self.stack,
            buffer: self.buffer,
            length: self.length,
            backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)),
        }
    }
}

impl Default for BLAKE3 {
    fn default() -> Self {
        Self::new()
    }
}
