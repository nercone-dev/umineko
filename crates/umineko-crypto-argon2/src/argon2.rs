use alloc::vec::Vec;
use core::fmt;
use crate::errors::Argon2Error;

use umineko_hash_blake::BLAKE2B;
use umineko_helpers::provider::{KDFProviderInputs, KDFProviderRequest, KDFProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Argon2Variant {
    D,
    I,
    ID,
}

impl Argon2Variant {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::D => "argon2d",
            Self::I => "argon2i",
            Self::ID => "argon2id",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "argon2d" => Some(Self::D),
            "argon2i" => Some(Self::I),
            "argon2id" => Some(Self::ID),
            _ => None,
        }
    }

    pub fn data_independent(&self) -> bool {
        matches!(self, Self::I | Self::ID)
    }

    pub fn value(&self) -> u32 {
        match self {
            Self::D => 0,
            Self::I => 1,
            Self::ID => 2,
        }
    }

    /// Whether the addresses of one segment come from a counter rather than from the last block.
    pub fn addressed(&self, pass: u32, slice: usize) -> bool {
        match self {
            Self::D => false,
            Self::I => true,
            Self::ID => pass == 0 && slice < 2,
        }
    }
}

impl fmt::Display for Argon2Variant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Argon2 {
    pub variant: Argon2Variant,
    pub version: u32,
    pub memory: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for Argon2 {
    fn default() -> Self {
        Self { variant: Argon2Variant::ID, version: Self::VERSION_13, memory: 64 * 1024, iterations: 3, parallelism: 4 }
    }
}

impl Argon2 {
    pub const VERSION_10: u32 = 0x10;
    pub const VERSION_13: u32 = 0x13;
    pub const MINIMUM_SALT_SIZE: usize = 8;
    pub const MINIMUM_TAG_SIZE: usize = 4;
    pub const BLOCK_SIZE: usize = 1024;
    pub const BLOCK_WORDS: usize = 128;
    pub const SLICES: usize = 4;
    pub const DIGEST_SIZE: usize = 64;

    pub fn request(&self) -> KDFProviderRequest {
        KDFProviderRequest::new(self.variant.as_str()).with_memory(self.memory, self.iterations, self.parallelism, self.version)
    }

    /// The blocks the mixing uses, which is the memory rounded down to four blocks for each lane.
    pub fn blocks(&self) -> usize {
        let requested = self.memory.max(8 * self.parallelism) as usize;
        requested / (Self::SLICES * self.parallelism as usize) * (Self::SLICES * self.parallelism as usize)
    }

    pub fn memory(&self) -> usize {
        self.blocks() * Self::BLOCK_SIZE
    }

    pub fn check(&self, length: usize) -> Result<(), Argon2Error> {
        if self.parallelism == 0 || self.iterations == 0 || self.memory < 8 * self.parallelism {
            return Err(Argon2Error::Parameters);
        }
        if self.version != Self::VERSION_10 && self.version != Self::VERSION_13 {
            return Err(Argon2Error::Parameters);
        }
        match length < Self::MINIMUM_TAG_SIZE {
            true => Err(Argon2Error::Length),
            false => Ok(()),
        }
    }

    /// The first digest, which covers every parameter and every input.
    pub fn preliminary(&self, password: &[u8], salt: &[u8], secret: &[u8], associated: &[u8], length: usize) -> [u8; Self::DIGEST_SIZE] {
        let mut hash = BLAKE2B::new(Self::DIGEST_SIZE);
        for value in [self.parallelism, length as u32, self.memory, self.iterations, self.version, self.variant.value()] {
            hash.update(&value.to_le_bytes());
        }
        for part in [password, salt, secret, associated] {
            hash.update(&(part.len() as u32).to_le_bytes());
            hash.update(part);
        }
        let mut digest = [0; Self::DIGEST_SIZE];
        hash.finalize(&mut digest);
        digest
    }

    /// The variable length digest, which chains sixty four byte blocks and keeps half of each.
    pub fn variable(input: &[u8], output: &mut [u8]) {
        let mut hash = BLAKE2B::new(output.len().min(Self::DIGEST_SIZE));
        hash.update(&(output.len() as u32).to_le_bytes());
        hash.update(input);
        if output.len() <= Self::DIGEST_SIZE {
            return hash.finalize(output);
        }
        let mut block = [0; Self::DIGEST_SIZE];
        hash.finalize(&mut block);
        let mut written = 0;
        while output.len() - written > Self::DIGEST_SIZE {
            output[written..written + Self::DIGEST_SIZE / 2].copy_from_slice(&block[..Self::DIGEST_SIZE / 2]);
            written += Self::DIGEST_SIZE / 2;
            if output.len() - written > Self::DIGEST_SIZE {
                let mut hash = BLAKE2B::new(Self::DIGEST_SIZE);
                hash.update(&block);
                hash.finalize(&mut block);
            }
        }
        let mut hash = BLAKE2B::new(output.len() - written);
        hash.update(&block);
        hash.finalize(&mut output[written..]);
    }

    /// The multiplication that Argon2 adds to every addition of the mixing step.
    pub fn multiply(left: u64, right: u64) -> u64 {
        left.wrapping_add(right).wrapping_add(2u64.wrapping_mul(left as u32 as u64).wrapping_mul(right as u32 as u64))
    }

    /// The mixing step of BLAKE2b, over four of the sixteen words.
    pub fn mix(words: &mut [u64; 16], lanes: [usize; 4]) {
        let [a, b, c, d] = lanes;
        words[a] = Self::multiply(words[a], words[b]);
        words[d] = (words[d] ^ words[a]).rotate_right(32);
        words[c] = Self::multiply(words[c], words[d]);
        words[b] = (words[b] ^ words[c]).rotate_right(24);
        words[a] = Self::multiply(words[a], words[b]);
        words[d] = (words[d] ^ words[a]).rotate_right(16);
        words[c] = Self::multiply(words[c], words[d]);
        words[b] = (words[b] ^ words[c]).rotate_right(63);
    }

    pub fn permute(words: &mut [u64; 16]) {
        for column in 0..4 {
            Self::mix(words, [column, column + 4, column + 8, column + 12]);
        }
        for diagonal in 0..4 {
            Self::mix(words, [diagonal, 4 + (diagonal + 1) % 4, 8 + (diagonal + 2) % 4, 12 + (diagonal + 3) % 4]);
        }
    }

    /// The compression of two blocks, over the rows and then the columns of the sixteen by eight matrix.
    pub fn compress(target: &mut [u64; Self::BLOCK_WORDS], left: &[u64; Self::BLOCK_WORDS], right: &[u64; Self::BLOCK_WORDS], accumulate: bool) {
        let mut mixed = [0u64; Self::BLOCK_WORDS];
        for (word, (first, second)) in mixed.iter_mut().zip(left.iter().zip(right)) {
            *word = first ^ second;
        }
        let combined = mixed;
        for row in 0..8 {
            let mut words: [u64; 16] = core::array::from_fn(|index| mixed[row * 16 + index]);
            Self::permute(&mut words);
            for (index, word) in words.into_iter().enumerate() {
                mixed[row * 16 + index] = word;
            }
        }
        for column in 0..8 {
            let position = |index: usize| (index / 2) * 16 + column * 2 + index % 2;
            let mut words: [u64; 16] = core::array::from_fn(|index| mixed[position(index)]);
            Self::permute(&mut words);
            for (index, word) in words.into_iter().enumerate() {
                mixed[position(index)] = word;
            }
        }
        for (index, word) in mixed.into_iter().enumerate() {
            target[index] = match accumulate {
                true => target[index] ^ word ^ combined[index],
                false => word ^ combined[index],
            };
        }
    }

    pub fn words(block: &[u8]) -> [u64; Self::BLOCK_WORDS] {
        core::array::from_fn(|index| u64::from_le_bytes(block[index * 8..index * 8 + 8].try_into().unwrap_or([0; 8])))
    }

    pub fn bytes(block: &[u64; Self::BLOCK_WORDS]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::BLOCK_SIZE);
        for word in block {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    /// The block of the lane that the pseudorandom value names, as the reference indexing describes.
    #[allow(clippy::too_many_arguments)]
    pub fn reference(&self, random: u64, pass: u32, lane: usize, slice: usize, index: usize, segment: usize, length: usize) -> usize {
        let referenced = match pass == 0 && slice == 0 {
            true => lane,
            false => ((random >> 32) % self.parallelism as u64) as usize,
        };
        let same = referenced == lane;
        let area = match (pass, slice, same) {
            (0, 0, _) => index - 1,
            (0, _, true) => slice * segment + index - 1,
            (0, _, false) => slice * segment - (index == 0) as usize,
            (_, _, true) => length - segment + index - 1,
            (_, _, false) => length - segment - (index == 0) as usize,
        };
        let relative = ((random & 0xFFFF_FFFF) * (random & 0xFFFF_FFFF)) >> 32;
        let relative = area as u64 - 1 - ((area as u64 * relative) >> 32);
        let start = match pass == 0 || slice == Self::SLICES - 1 {
            true => 0,
            false => (slice + 1) * segment,
        };
        referenced * length + (start + relative as usize) % length
    }

    /// The block that holds the pseudorandom values of one segment of a data independent pass.
    pub fn addresses(&self, pass: u32, lane: usize, slice: usize, counter: u64, blocks: usize) -> [u64; Self::BLOCK_WORDS] {
        let mut input = [0u64; Self::BLOCK_WORDS];
        input[0] = pass as u64;
        input[1] = lane as u64;
        input[2] = slice as u64;
        input[3] = blocks as u64;
        input[4] = self.iterations as u64;
        input[5] = self.variant.value() as u64;
        input[6] = counter;
        let mut first = [0u64; Self::BLOCK_WORDS];
        Self::compress(&mut first, &[0; Self::BLOCK_WORDS], &input, false);
        let mut second = [0u64; Self::BLOCK_WORDS];
        Self::compress(&mut second, &[0; Self::BLOCK_WORDS], &first, false);
        second
    }

    pub fn derive(&self, password: &[u8], salt: &[u8], secret: &[u8], associated: &[u8], output: &mut [u8]) -> Result<(), Argon2Error> {
        if salt.len() < Self::MINIMUM_SALT_SIZE {
            return Err(Argon2Error::Salt);
        }
        self.check(output.len())?;
        match KDFProviders::derive(&self.request(), &KDFProviderInputs::new(password, salt).with_secret(secret).with_associated(associated), output)? {
            Some(()) => Ok(()),
            None => {
                self.fill(password, salt, secret, associated, output);
                Ok(())
            }
        }
    }

    /// The whole memory filled pass by pass, and the last block of every lane folded into the tag.
    pub fn fill(&self, password: &[u8], salt: &[u8], secret: &[u8], associated: &[u8], output: &mut [u8]) {
        let count = self.blocks();
        let length = count / self.parallelism as usize;
        let segment = length / Self::SLICES;
        let preliminary = self.preliminary(password, salt, secret, associated, output.len());
        let mut blocks = alloc::vec![[0u64; Self::BLOCK_WORDS]; count];
        let mut opening = [0; Self::DIGEST_SIZE + 8];
        opening[..Self::DIGEST_SIZE].copy_from_slice(&preliminary);
        let mut block = alloc::vec![0; Self::BLOCK_SIZE];
        for lane in 0..self.parallelism as usize {
            opening[Self::DIGEST_SIZE + 4..].copy_from_slice(&(lane as u32).to_le_bytes());
            for column in 0..2 {
                opening[Self::DIGEST_SIZE..Self::DIGEST_SIZE + 4].copy_from_slice(&(column as u32).to_le_bytes());
                Self::variable(&opening, &mut block);
                blocks[lane * length + column] = Self::words(&block);
            }
        }
        for pass in 0..self.iterations {
            for slice in 0..Self::SLICES {
                for lane in 0..self.parallelism as usize {
                    let addressed = self.variant.addressed(pass, slice);
                    let mut counter = 0;
                    let mut addresses = [0; Self::BLOCK_WORDS];
                    let start = match pass == 0 && slice == 0 {
                        true => 2,
                        false => 0,
                    };
                    if addressed && start == 2 {
                        counter += 1;
                        addresses = self.addresses(pass, lane, slice, counter, count);
                    }
                    for index in start..segment {
                        if addressed && index % Self::BLOCK_WORDS == 0 {
                            counter += 1;
                            addresses = self.addresses(pass, lane, slice, counter, count);
                        }
                        let current = lane * length + slice * segment + index;
                        let previous = match current % length == 0 {
                            true => current + length - 1,
                            false => current - 1,
                        };
                        let random = match addressed {
                            true => addresses[index % Self::BLOCK_WORDS],
                            false => blocks[previous][0],
                        };
                        let referenced = self.reference(random, pass, lane, slice, index, segment, length);
                        let (left, right) = (blocks[previous], blocks[referenced]);
                        let accumulate = pass != 0 && self.version == Self::VERSION_13;
                        Self::compress(&mut blocks[current], &left, &right, accumulate);
                    }
                }
            }
        }
        let mut last = blocks[length - 1];
        for lane in 1..self.parallelism as usize {
            for (word, value) in last.iter_mut().zip(blocks[lane * length + length - 1]) {
                *word ^= value;
            }
        }
        Self::variable(&Self::bytes(&last), output);
    }

    pub fn verify(&self, password: &[u8], salt: &[u8], secret: &[u8], associated: &[u8], expected: &[u8]) -> Result<(), Argon2Error> {
        let mut output = alloc::vec![0; expected.len()];
        self.derive(password, salt, secret, associated, &mut output)?;
        let mut difference = 0;
        for (left, right) in output.iter().zip(expected) {
            difference |= left ^ right;
        }
        match difference {
            0 => Ok(()),
            _ => Err(Argon2Error::Verification),
        }
    }
}
