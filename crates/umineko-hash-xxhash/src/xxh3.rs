use core::fmt;

use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XXH3 {
    V64,
    V128,
}

impl XXH3 {
    pub const SECRET_SIZE: usize = 192;
    pub const STRIPE_SIZE: usize = 64;
    pub const BUFFER_SIZE: usize = 256;
    /// The longest input the short paths cover; longer inputs run the accumulators.
    pub const MIDSIZE: usize = 240;
    pub const STRIPES_PER_BLOCK: usize = (Self::SECRET_SIZE - Self::STRIPE_SIZE) / 8;
    /// Where the secret for the closing stripe starts, counted back from its end.
    pub const LAST_STRIPE_OFFSET: usize = Self::SECRET_SIZE - Self::STRIPE_SIZE - 7;
    /// Where the secret for merging the accumulators starts.
    pub const MERGE_OFFSET: usize = 11;
    pub const PRIMES32: [u32; 3] = [0x9E37_79B1, 0x85EB_CA77, 0xC2B2_AE3D];
    pub const PRIMES64: [u64; 5] = [
        0x9E37_79B1_85EB_CA87,
        0xC2B2_AE3D_27D4_EB4F,
        0x1656_67B1_9E37_79F9,
        0x85EB_CA77_C2B2_AE63,
        0x27D4_EB2F_1656_67C5,
    ];
    pub const MIXERS: [u64; 2] = [0x1656_6791_9E37_79F9, 0x9FB2_1C65_1E98_DF25];
    pub const SECRET: [u8; 192] = [
        0xB8, 0xFE, 0x6C, 0x39, 0x23, 0xA4, 0x4B, 0xBE, 0x7C, 0x01, 0x81, 0x2C, 0xF7, 0x21, 0xAD, 0x1C,
        0xDE, 0xD4, 0x6D, 0xE9, 0x83, 0x90, 0x97, 0xDB, 0x72, 0x40, 0xA4, 0xA4, 0xB7, 0xB3, 0x67, 0x1F,
        0xCB, 0x79, 0xE6, 0x4E, 0xCC, 0xC0, 0xE5, 0x78, 0x82, 0x5A, 0xD0, 0x7D, 0xCC, 0xFF, 0x72, 0x21,
        0xB8, 0x08, 0x46, 0x74, 0xF7, 0x43, 0x24, 0x8E, 0xE0, 0x35, 0x90, 0xE6, 0x81, 0x3A, 0x26, 0x4C,
        0x3C, 0x28, 0x52, 0xBB, 0x91, 0xC3, 0x00, 0xCB, 0x88, 0xD0, 0x65, 0x8B, 0x1B, 0x53, 0x2E, 0xA3,
        0x71, 0x64, 0x48, 0x97, 0xA2, 0x0D, 0xF9, 0x4E, 0x38, 0x19, 0xEF, 0x46, 0xA9, 0xDE, 0xAC, 0xD8,
        0xA8, 0xFA, 0x76, 0x3F, 0xE3, 0x9C, 0x34, 0x3F, 0xF9, 0xDC, 0xBB, 0xC7, 0xC7, 0x0B, 0x4F, 0x1D,
        0x8A, 0x51, 0xE0, 0x4B, 0xCD, 0xB4, 0x59, 0x31, 0xC8, 0x9F, 0x7E, 0xC9, 0xD9, 0x78, 0x73, 0x64,
        0xEA, 0xC5, 0xAC, 0x83, 0x34, 0xD3, 0xEB, 0xC3, 0xC5, 0x81, 0xA0, 0xFF, 0xFA, 0x13, 0x63, 0xEB,
        0x17, 0x0D, 0xDD, 0x51, 0xB7, 0xF0, 0xDA, 0x49, 0xD3, 0x16, 0x55, 0x26, 0x29, 0xD4, 0x68, 0x9E,
        0x2B, 0x16, 0xBE, 0x58, 0x7D, 0x47, 0xA1, 0xFC, 0x8F, 0xF8, 0xB8, 0xD1, 0x7A, 0xD0, 0x31, 0xCE,
        0x45, 0xCB, 0x3A, 0x8F, 0x95, 0x16, 0x04, 0x28, 0xAF, 0xD7, 0xFB, 0xCA, 0xBB, 0x4B, 0x40, 0x7E,
    ];

    pub fn digest_size(&self) -> usize {
        match self {
            Self::V64 => 8,
            Self::V128 => 16,
        }
    }

    pub fn block_size(&self) -> usize {
        match self {
            Self::V64 => 64,
            Self::V128 => 64,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V64 => "XXH3-64",
            Self::V128 => "XXH3-128",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "XXH3-64" => Some(Self::V64),
            "XXH3-128" => Some(Self::V128),
            _ => None,
        }
    }

    /// The little endian word at `offset`.
    pub fn word(data: &[u8], offset: usize) -> u64 {
        let mut word = [0; 8];
        word.copy_from_slice(&data[offset..offset + 8]);
        u64::from_le_bytes(word)
    }

    /// The little endian half word at `offset`.
    pub fn half(data: &[u8], offset: usize) -> u32 {
        let mut half = [0; 4];
        half.copy_from_slice(&data[offset..offset + 4]);
        u32::from_le_bytes(half)
    }

    /// The full product of two words, as its low and high halves.
    pub fn multiply(left: u64, right: u64) -> (u64, u64) {
        let product = left as u128 * right as u128;
        (product as u64, (product >> 64) as u64)
    }

    /// The full product of two words, folded into one.
    pub fn fold(left: u64, right: u64) -> u64 {
        let (low, high) = Self::multiply(left, right);
        low ^ high
    }

    /// The mixing xxHash64 closes with, which the short inputs reuse.
    pub fn avalanche64(value: u64) -> u64 {
        let value = (value ^ (value >> 33)).wrapping_mul(Self::PRIMES64[1]);
        let value = (value ^ (value >> 29)).wrapping_mul(Self::PRIMES64[2]);
        value ^ (value >> 32)
    }

    /// The mixing XXH3 closes with.
    pub fn avalanche(value: u64) -> u64 {
        let value = (value ^ (value >> 37)).wrapping_mul(Self::MIXERS[0]);
        value ^ (value >> 32)
    }

    /// The stronger mixing inputs of four to eight bytes close with.
    pub fn avalanche_short(value: u64, length: u64) -> u64 {
        let value = (value ^ value.rotate_left(49) ^ value.rotate_left(24)).wrapping_mul(Self::MIXERS[1]);
        let value = (value ^ ((value >> 35).wrapping_add(length))).wrapping_mul(Self::MIXERS[1]);
        value ^ (value >> 28)
    }

    /// Mixes sixteen input bytes with sixteen secret bytes.
    pub fn mix(input: &[u8], offset: usize, secret: &[u8], key: usize, seed: u64) -> u64 {
        let low = Self::word(input, offset) ^ Self::word(secret, key).wrapping_add(seed);
        let high = Self::word(input, offset + 8) ^ Self::word(secret, key + 8).wrapping_sub(seed);
        Self::fold(low, high)
    }

    /// Mixes thirty-two input bytes into both halves of a wide accumulator.
    pub fn mix_wide(accumulator: (u64, u64), input: &[u8], first: usize, second: usize, secret: &[u8], key: usize, seed: u64) -> (u64, u64) {
        let low = accumulator
            .0
            .wrapping_add(Self::mix(input, first, secret, key, seed))
            ^ Self::word(input, second).wrapping_add(Self::word(input, second + 8));
        let high = accumulator
            .1
            .wrapping_add(Self::mix(input, second, secret, key + 16, seed))
            ^ Self::word(input, first).wrapping_add(Self::word(input, first + 8));
        (low, high)
    }

    /// The secret a seed derives; the default secret carries the seed of zero.
    pub fn secret(seed: u64) -> [u8; Self::SECRET_SIZE] {
        let mut secret = Self::SECRET;
        if seed != 0 {
            for index in 0..Self::SECRET_SIZE / 16 {
                let low = Self::word(&Self::SECRET, index * 16).wrapping_add(seed);
                let high = Self::word(&Self::SECRET, index * 16 + 8).wrapping_sub(seed);
                secret[index * 16..index * 16 + 8].copy_from_slice(&low.to_le_bytes());
                secret[index * 16 + 8..index * 16 + 16].copy_from_slice(&high.to_le_bytes());
            }
        }
        secret
    }

    /// The eight lanes the accumulators start at.
    pub fn initial() -> [u64; 8] {
        [
            Self::PRIMES32[2] as u64,
            Self::PRIMES64[0],
            Self::PRIMES64[1],
            Self::PRIMES64[2],
            Self::PRIMES64[3],
            Self::PRIMES32[1] as u64,
            Self::PRIMES64[4],
            Self::PRIMES32[0] as u64,
        ]
    }

    /// Folds one stripe into the accumulators.
    pub fn accumulate(accumulator: &mut [u64; 8], stripe: &[u8], secret: &[u8], key: usize) {
        for index in 0..8 {
            let value = Self::word(stripe, index * 8);
            let keyed = value ^ Self::word(secret, key + index * 8);
            accumulator[index ^ 1] = accumulator[index ^ 1].wrapping_add(value);
            accumulator[index] = accumulator[index].wrapping_add((keyed & 0xFFFF_FFFF).wrapping_mul(keyed >> 32));
        }
    }

    /// Scrambles the accumulators, which closes every block.
    pub fn scramble(accumulator: &mut [u64; 8], secret: &[u8]) {
        for (index, lane) in accumulator.iter_mut().enumerate() {
            let value = *lane ^ (*lane >> 47) ^ Self::word(secret, Self::SECRET_SIZE - Self::STRIPE_SIZE + index * 8);
            *lane = value.wrapping_mul(Self::PRIMES32[0] as u64);
        }
    }

    /// Folds one stripe in and scrambles the accumulators when the block ends.
    pub fn stripe(accumulator: &mut [u64; 8], stripe: &[u8], secret: &[u8], index: usize) {
        Self::accumulate(accumulator, stripe, secret, index % Self::STRIPES_PER_BLOCK * 8);
        if (index + 1) % Self::STRIPES_PER_BLOCK == 0 {
            Self::scramble(accumulator, secret);
        }
    }

    /// Folds the accumulators into one word.
    pub fn merge(accumulator: &[u64; 8], secret: &[u8], key: usize, start: u64) -> u64 {
        let mut value = start;
        for index in 0..4 {
            let low = accumulator[index * 2] ^ Self::word(secret, key + index * 16);
            let high = accumulator[index * 2 + 1] ^ Self::word(secret, key + index * 16 + 8);
            value = value.wrapping_add(Self::fold(low, high));
        }
        Self::avalanche(value)
    }

    /// Runs every stripe of a long input through the accumulators.
    pub fn accumulators(data: &[u8], secret: &[u8]) -> [u64; 8] {
        let mut accumulator = Self::initial();
        let stripes = (data.len() - 1) / Self::STRIPE_SIZE;
        for index in 0..stripes {
            Self::stripe(&mut accumulator, &data[index * Self::STRIPE_SIZE..], secret, index);
        }
        Self::accumulate(&mut accumulator, &data[data.len() - Self::STRIPE_SIZE..], secret, Self::LAST_STRIPE_OFFSET);
        accumulator
    }

    /// The number of stripes a running state of `length` bytes has folded in.
    pub fn stripes(length: u64) -> u64 {
        match length as usize <= Self::MIDSIZE {
            true => 0,
            false => (length - Self::STRIPE_SIZE as u64) / Self::STRIPE_SIZE as u64,
        }
    }

    /// The number of bytes a running state of `length` bytes still holds.
    pub fn filled(length: u64) -> usize {
        (length - Self::stripes(length) * Self::STRIPE_SIZE as u64) as usize
    }

    pub fn absorb(accumulator: &mut [u64; 8], secret: &[u8], buffer: &mut [u8; 256], length: &mut u64, data: &[u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let filled = Self::filled(*length);
            let taken = (Self::BUFFER_SIZE - filled).min(data.len() - offset);
            buffer[filled..filled + taken].copy_from_slice(&data[offset..offset + taken]);
            let folded = Self::stripes(*length);
            *length += taken as u64;
            let target = Self::stripes(*length);
            for index in folded..target {
                let start = (index - folded) as usize * Self::STRIPE_SIZE;
                Self::stripe(accumulator, &buffer[start..], secret, index as usize);
            }
            let shift = (target - folded) as usize * Self::STRIPE_SIZE;
            buffer.copy_within(shift..filled + taken, 0);
            offset += taken;
        }
    }

    /// Closes the accumulators of a running state, which still holds the closing stripes.
    pub fn digest(accumulator: &[u64; 8], secret: &[u8], buffer: &[u8; 256], length: u64) -> [u64; 8] {
        let mut accumulator = *accumulator;
        let folded = Self::stripes(length) as usize;
        let filled = Self::filled(length);
        for index in 0..(filled - 1) / Self::STRIPE_SIZE {
            Self::stripe(&mut accumulator, &buffer[index * Self::STRIPE_SIZE..], secret, folded + index);
        }
        Self::accumulate(&mut accumulator, &buffer[filled - Self::STRIPE_SIZE..], secret, Self::LAST_STRIPE_OFFSET);
        accumulator
    }
}

impl fmt::Display for XXH3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct XXH3_64 {
    accumulator: [u64; 8],
    secret: [u8; 192],
    buffer: [u8; 256],
    length: u64,
    seed: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl XXH3_64 {
    pub const NAME: &'static str = "XXH3-64";
    pub const DIGEST_SIZE: usize = 8;
    pub const BLOCK_SIZE: usize = 64;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(0),
            backend => Self { accumulator: [0; 8], secret: [0; 192], buffer: [0; 256], length: 0, seed: 0, backend },
        }
    }

    pub fn builtin(seed: u64) -> Self {
        Self { accumulator: XXH3::initial(), secret: XXH3::secret(seed), buffer: [0; 256], length: 0, seed, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn with_seed(seed: u64) -> Self {
        match HashProviders::backend(&Self::request().with_seed(seed)) {
            ProviderBackend::Builtin => Self::builtin(seed),
            backend => Self { accumulator: [0; 8], secret: [0; 192], buffer: [0; 256], length: 0, seed, backend },
        }
    }

    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// The hash of an input of at most sixteen bytes.
    pub fn short(data: &[u8], secret: &[u8], seed: u64) -> u64 {
        match data.len() {
            0 => XXH3::avalanche64(seed ^ XXH3::word(secret, 56) ^ XXH3::word(secret, 64)),
            1..=3 => {
                let combined = ((data[0] as u32) << 16) | ((data[data.len() >> 1] as u32) << 24) | (data[data.len() - 1] as u32) | ((data.len() as u32) << 8);
                let flip = ((XXH3::half(secret, 0) ^ XXH3::half(secret, 4)) as u64).wrapping_add(seed);
                XXH3::avalanche64(combined as u64 ^ flip)
            }
            4..=8 => {
                let seed = seed ^ ((seed as u32).swap_bytes() as u64) << 32;
                let low = XXH3::half(data, 0) as u64;
                let high = XXH3::half(data, data.len() - 4) as u64;
                let flip = (XXH3::word(secret, 8) ^ XXH3::word(secret, 16)).wrapping_sub(seed);
                XXH3::avalanche_short((high + (low << 32)) ^ flip, data.len() as u64)
            }
            _ => {
                let flip_low = (XXH3::word(secret, 24) ^ XXH3::word(secret, 32)).wrapping_add(seed);
                let flip_high = (XXH3::word(secret, 40) ^ XXH3::word(secret, 48)).wrapping_sub(seed);
                let low = XXH3::word(data, 0) ^ flip_low;
                let high = XXH3::word(data, data.len() - 8) ^ flip_high;
                let value = (data.len() as u64).wrapping_add(low.swap_bytes()).wrapping_add(high).wrapping_add(XXH3::fold(low, high));
                XXH3::avalanche(value)
            }
        }
    }

    /// The hash of an input of seventeen to a hundred and twenty-eight bytes.
    pub fn medium(data: &[u8], secret: &[u8], seed: u64) -> u64 {
        let length = data.len();
        let mut value = (length as u64).wrapping_mul(XXH3::PRIMES64[0]);
        for index in (0..4).rev() {
            if length > index * 32 {
                value = value.wrapping_add(XXH3::mix(data, index * 16, secret, index * 32, seed));
                value = value.wrapping_add(XXH3::mix(data, length - index * 16 - 16, secret, index * 32 + 16, seed));
            }
        }
        XXH3::avalanche(value)
    }

    /// The hash of an input of a hundred and twenty-nine to two hundred and forty bytes.
    pub fn long(data: &[u8], secret: &[u8], seed: u64) -> u64 {
        let length = data.len();
        let mut value = (length as u64).wrapping_mul(XXH3::PRIMES64[0]);
        for index in 0..8 {
            value = value.wrapping_add(XXH3::mix(data, index * 16, secret, index * 16, seed));
        }
        value = XXH3::avalanche(value);
        for index in 8..length / 16 {
            value = value.wrapping_add(XXH3::mix(data, index * 16, secret, (index - 8) * 16 + 3, seed));
        }
        value = value.wrapping_add(XXH3::mix(data, length - 16, secret, 136 - 17, seed));
        XXH3::avalanche(value)
    }

    /// The whole hash of `data`, whichever path its length takes.
    pub fn hash(data: &[u8], secret: &[u8], seed: u64) -> u64 {
        match data.len() {
            0..=16 => Self::short(data, secret, seed),
            17..=128 => Self::medium(data, secret, seed),
            129..=240 => Self::long(data, secret, seed),
            length => XXH3::merge(&XXH3::accumulators(data, secret), secret, XXH3::MERGE_OFFSET, (length as u64).wrapping_mul(XXH3::PRIMES64[0])),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => XXH3::absorb(&mut self.accumulator, &self.secret, &mut self.buffer, &mut self.length, data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn value(&self) -> u64 {
        match self.length as usize <= XXH3::MIDSIZE {
            true => Self::hash(&self.buffer[..self.length as usize], &XXH3::SECRET, self.seed),
            false => {
                let accumulator = XXH3::digest(&self.accumulator, &self.secret, &self.buffer, self.length);
                XXH3::merge(&accumulator, &self.secret, XXH3::MERGE_OFFSET, self.length.wrapping_mul(XXH3::PRIMES64[0]))
            }
        }
    }

    pub fn finalize(self) -> [u8; 8] {
        match &self.backend {
            ProviderBackend::Builtin => self.value().to_be_bytes(),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 8];
                provider.finalize(*handle, &mut digest);
                digest
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => (self.accumulator, self.buffer, self.length) = (XXH3::initial(), [0; 256], 0),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8]) -> [u8; 8] {
        let mut digest = [0; 8];
        match HashProviders::digest(&Self::request(), data, &mut digest) {
            Some(_) => digest,
            None => Self::hash(data, &XXH3::SECRET, 0).to_be_bytes(),
        }
    }
}

impl Clone for XXH3_64 {
    fn clone(&self) -> Self {
        Self { accumulator: self.accumulator, secret: self.secret, buffer: self.buffer, length: self.length, seed: self.seed, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for XXH3_64 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct XXH3_128 {
    accumulator: [u64; 8],
    secret: [u8; 192],
    buffer: [u8; 256],
    length: u64,
    seed: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl XXH3_128 {
    pub const NAME: &'static str = "XXH3-128";
    pub const DIGEST_SIZE: usize = 16;
    pub const BLOCK_SIZE: usize = 64;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(0),
            backend => Self { accumulator: [0; 8], secret: [0; 192], buffer: [0; 256], length: 0, seed: 0, backend },
        }
    }

    pub fn builtin(seed: u64) -> Self {
        Self { accumulator: XXH3::initial(), secret: XXH3::secret(seed), buffer: [0; 256], length: 0, seed, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn with_seed(seed: u64) -> Self {
        match HashProviders::backend(&Self::request().with_seed(seed)) {
            ProviderBackend::Builtin => Self::builtin(seed),
            backend => Self { accumulator: [0; 8], secret: [0; 192], buffer: [0; 256], length: 0, seed, backend },
        }
    }

    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// The hash of an input of at most sixteen bytes, as its low and high halves.
    pub fn short(data: &[u8], secret: &[u8], seed: u64) -> (u64, u64) {
        match data.len() {
            0 => (
                XXH3::avalanche64(seed ^ XXH3::word(secret, 64) ^ XXH3::word(secret, 72)),
                XXH3::avalanche64(seed ^ XXH3::word(secret, 80) ^ XXH3::word(secret, 88)),
            ),
            1..=3 => {
                let combined = ((data[0] as u32) << 16) | ((data[data.len() >> 1] as u32) << 24) | (data[data.len() - 1] as u32) | ((data.len() as u32) << 8);
                let mirrored = combined.swap_bytes().rotate_left(13);
                let flip_low = ((XXH3::half(secret, 0) ^ XXH3::half(secret, 4)) as u64).wrapping_add(seed);
                let flip_high = ((XXH3::half(secret, 8) ^ XXH3::half(secret, 12)) as u64).wrapping_sub(seed);
                (XXH3::avalanche64(combined as u64 ^ flip_low), XXH3::avalanche64(mirrored as u64 ^ flip_high))
            }
            4..=8 => {
                let seed = seed ^ ((seed as u32).swap_bytes() as u64) << 32;
                let low = XXH3::half(data, 0) as u64;
                let high = XXH3::half(data, data.len() - 4) as u64;
                let flip = (XXH3::word(secret, 16) ^ XXH3::word(secret, 24)).wrapping_add(seed);
                let keyed = (low + (high << 32)) ^ flip;
                let (mut low, mut high) = XXH3::multiply(keyed, XXH3::PRIMES64[0].wrapping_add((data.len() as u64) << 2));
                high = high.wrapping_add(low << 1);
                low ^= high >> 3;
                low = (low ^ (low >> 35)).wrapping_mul(XXH3::MIXERS[1]);
                low ^= low >> 28;
                (low, XXH3::avalanche(high))
            }
            _ => {
                let flip_low = (XXH3::word(secret, 32) ^ XXH3::word(secret, 40)).wrapping_sub(seed);
                let flip_high = (XXH3::word(secret, 48) ^ XXH3::word(secret, 56)).wrapping_add(seed);
                let input_low = XXH3::word(data, 0);
                let input_high = XXH3::word(data, data.len() - 8);
                let (mut low, mut high) = XXH3::multiply(input_low ^ input_high ^ flip_low, XXH3::PRIMES64[0]);
                low = low.wrapping_add((data.len() as u64 - 1) << 54);
                let input_high = input_high ^ flip_high;
                high = high.wrapping_add(input_high).wrapping_add((input_high as u32 as u64).wrapping_mul(XXH3::PRIMES32[1] as u64 - 1));
                low ^= high.swap_bytes();
                let (folded_low, folded_high) = XXH3::multiply(low, XXH3::PRIMES64[1]);
                (XXH3::avalanche(folded_low), XXH3::avalanche(folded_high.wrapping_add(high.wrapping_mul(XXH3::PRIMES64[1]))))
            }
        }
    }

    /// The hash of an input of seventeen to a hundred and twenty-eight bytes.
    pub fn medium(data: &[u8], secret: &[u8], seed: u64) -> (u64, u64) {
        let length = data.len();
        let mut accumulator = ((length as u64).wrapping_mul(XXH3::PRIMES64[0]), 0);
        for index in (0..4).rev() {
            if length > index * 32 {
                accumulator = XXH3::mix_wide(accumulator, data, index * 16, length - index * 16 - 16, secret, index * 32, seed);
            }
        }
        Self::close(accumulator, length as u64, seed)
    }

    /// The hash of an input of a hundred and twenty-nine to two hundred and forty bytes.
    pub fn long(data: &[u8], secret: &[u8], seed: u64) -> (u64, u64) {
        let length = data.len();
        let mut accumulator = ((length as u64).wrapping_mul(XXH3::PRIMES64[0]), 0);
        for index in 0..4 {
            accumulator = XXH3::mix_wide(accumulator, data, index * 32, index * 32 + 16, secret, index * 32, seed);
        }
        accumulator = (XXH3::avalanche(accumulator.0), XXH3::avalanche(accumulator.1));
        for index in 4..length / 32 {
            accumulator = XXH3::mix_wide(accumulator, data, index * 32, index * 32 + 16, secret, (index - 4) * 32 + 3, seed);
        }
        accumulator = XXH3::mix_wide(accumulator, data, length - 16, length - 32, secret, 136 - 17 - 16, 0u64.wrapping_sub(seed));
        Self::close(accumulator, length as u64, seed)
    }

    /// Folds a wide accumulator into the two halves of the digest.
    pub fn close(accumulator: (u64, u64), length: u64, seed: u64) -> (u64, u64) {
        let low = accumulator.0.wrapping_add(accumulator.1);
        let high = accumulator
            .0
            .wrapping_mul(XXH3::PRIMES64[0])
            .wrapping_add(accumulator.1.wrapping_mul(XXH3::PRIMES64[3]))
            .wrapping_add(length.wrapping_sub(seed).wrapping_mul(XXH3::PRIMES64[1]));
        (XXH3::avalanche(low), 0u64.wrapping_sub(XXH3::avalanche(high)))
    }

    /// Folds finished accumulators into the two halves of the digest.
    pub fn merge(accumulator: &[u64; 8], secret: &[u8], length: u64) -> (u64, u64) {
        let low = XXH3::merge(accumulator, secret, XXH3::MERGE_OFFSET, length.wrapping_mul(XXH3::PRIMES64[0]));
        let key = XXH3::SECRET_SIZE - XXH3::STRIPE_SIZE - XXH3::MERGE_OFFSET;
        let high = XXH3::merge(accumulator, secret, key, !length.wrapping_mul(XXH3::PRIMES64[1]));
        (low, high)
    }

    /// The whole hash of `data`, whichever path its length takes.
    pub fn hash(data: &[u8], secret: &[u8], seed: u64) -> (u64, u64) {
        match data.len() {
            0..=16 => Self::short(data, secret, seed),
            17..=128 => Self::medium(data, secret, seed),
            129..=240 => Self::long(data, secret, seed),
            length => Self::merge(&XXH3::accumulators(data, secret), secret, length as u64),
        }
    }

    /// The canonical byte order of a digest, with the high half first.
    pub fn canonical(digest: (u64, u64)) -> [u8; 16] {
        let mut canonical = [0; 16];
        canonical[..8].copy_from_slice(&digest.1.to_be_bytes());
        canonical[8..].copy_from_slice(&digest.0.to_be_bytes());
        canonical
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => XXH3::absorb(&mut self.accumulator, &self.secret, &mut self.buffer, &mut self.length, data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn value(&self) -> (u64, u64) {
        match self.length as usize <= XXH3::MIDSIZE {
            true => Self::hash(&self.buffer[..self.length as usize], &XXH3::SECRET, self.seed),
            false => Self::merge(&XXH3::digest(&self.accumulator, &self.secret, &self.buffer, self.length), &self.secret, self.length),
        }
    }

    pub fn finalize(self) -> [u8; 16] {
        match &self.backend {
            ProviderBackend::Builtin => Self::canonical(self.value()),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 16];
                provider.finalize(*handle, &mut digest);
                digest
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => (self.accumulator, self.buffer, self.length) = (XXH3::initial(), [0; 256], 0),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8]) -> [u8; 16] {
        let mut digest = [0; 16];
        match HashProviders::digest(&Self::request(), data, &mut digest) {
            Some(_) => digest,
            None => Self::canonical(Self::hash(data, &XXH3::SECRET, 0)),
        }
    }
}

impl Clone for XXH3_128 {
    fn clone(&self) -> Self {
        Self { accumulator: self.accumulator, secret: self.secret, buffer: self.buffer, length: self.length, seed: self.seed, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for XXH3_128 {
    fn default() -> Self {
        Self::new()
    }
}
