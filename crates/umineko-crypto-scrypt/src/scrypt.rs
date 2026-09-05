use alloc::vec::Vec;
use crate::errors::ScryptError;

use umineko_helpers::provider::{KDFProviderInputs, KDFProviderRequest, KDFProviders};

/// A keyed function that scrypt calls to stretch the password and to spread the output.
pub trait PRF {
    fn output_size(&self) -> usize;

    fn compute(&self, key: &[u8], data: &[u8], output: &mut [u8]);

    fn name(&self) -> Option<&'static str> {
        None
    }

    fn digest(&self) -> Option<&'static str> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scrypt<P: PRF> {
    prf: P,
    cost: u32,
    block: u32,
    parallelism: u32,
}

impl<P: PRF> Scrypt<P> {
    pub const RECOMMENDED_COST: u32 = 1 << 17;
    pub const RECOMMENDED_BLOCK: u32 = 8;
    pub const RECOMMENDED_PARALLELISM: u32 = 1;
    pub const MIXING_SIZE: usize = 64;
    pub const ROUNDS: usize = 8;

    /// A context whose cost is a power of two above one, with a positive block size and parallelism.
    pub fn new(prf: P, cost: u32, block: u32, parallelism: u32) -> Result<Self, ScryptError> {
        if cost < 2 || !cost.is_power_of_two() {
            return Err(ScryptError::Cost);
        }
        if block == 0 || parallelism == 0 || block as u64 * parallelism as u64 >= 1 << 30 {
            return Err(ScryptError::Parameters);
        }
        Ok(Self { prf, cost, block, parallelism })
    }

    pub fn prf(&self) -> &P {
        &self.prf
    }

    pub fn cost(&self) -> u32 {
        self.cost
    }

    pub fn block(&self) -> u32 {
        self.block
    }

    pub fn parallelism(&self) -> u32 {
        self.parallelism
    }

    /// The bytes the mixing needs, which is a hundred and twenty eight times the block size and the cost.
    pub fn memory(&self) -> usize {
        128 * self.block as usize * self.cost as usize
    }

    pub fn request(&self) -> Option<KDFProviderRequest> {
        let request = KDFProviderRequest::new("scrypt").with_prf(self.prf.name()?).with_cost(self.cost, self.block, self.parallelism);
        Some(match self.prf.digest() {
            Some(digest) => request.with_digest(digest),
            None => request,
        })
    }

    /// The core of Salsa20 reduced to eight rounds, over sixteen little endian words.
    pub fn salsa(block: &mut [u8; 64]) {
        let mut words = [0u32; 16];
        for (word, chunk) in words.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let mut working = words;
        for _ in 0..Self::ROUNDS / 2 {
            for column in 0..4 {
                Self::quarter(&mut working, core::array::from_fn(|lane| (5 * column + 4 * lane) % 16));
            }
            for row in 0..4 {
                Self::quarter(&mut working, core::array::from_fn(|lane| 4 * row + (row + lane) % 4));
            }
        }
        for (chunk, (value, initial)) in block.chunks_exact_mut(4).zip(working.into_iter().zip(words)) {
            chunk.copy_from_slice(&value.wrapping_add(initial).to_le_bytes());
        }
    }

    pub fn quarter(words: &mut [u32; 16], lanes: [usize; 4]) {
        let [a, b, c, d] = lanes;
        words[b] ^= words[a].wrapping_add(words[d]).rotate_left(7);
        words[c] ^= words[b].wrapping_add(words[a]).rotate_left(9);
        words[d] ^= words[c].wrapping_add(words[b]).rotate_left(13);
        words[a] ^= words[d].wrapping_add(words[c]).rotate_left(18);
    }

    /// The block mixing of scrypt, which chains the halves of the block through the core.
    pub fn mix(block: &mut [u8], scratch: &mut [u8], double: usize) {
        let mut value = [0u8; 64];
        value.copy_from_slice(&block[(double - 1) * Self::MIXING_SIZE..]);
        for index in 0..double {
            for (target, source) in value.iter_mut().zip(&block[index * Self::MIXING_SIZE..]) {
                *target ^= source;
            }
            Self::salsa(&mut value);
            let position = match index % 2 {
                0 => index / 2,
                _ => double / 2 + index / 2,
            };
            scratch[position * Self::MIXING_SIZE..(position + 1) * Self::MIXING_SIZE].copy_from_slice(&value);
        }
        block.copy_from_slice(scratch);
    }

    /// The sequentially memory hard mixing, which fills a table and then walks it at random.
    pub fn walk(&self, block: &mut [u8]) {
        let double = 2 * self.block as usize;
        let length = double * Self::MIXING_SIZE;
        let mut table = alloc::vec![0; length * self.cost as usize];
        let mut scratch = alloc::vec![0; length];
        for index in 0..self.cost as usize {
            table[index * length..(index + 1) * length].copy_from_slice(block);
            Self::mix(block, &mut scratch, double);
        }
        for _ in 0..self.cost {
            let mut tail = [0; 8];
            tail.copy_from_slice(&block[length - Self::MIXING_SIZE..length - Self::MIXING_SIZE + 8]);
            let position = (u64::from_le_bytes(tail) % self.cost as u64) as usize;
            for (target, source) in block.iter_mut().zip(&table[position * length..]) {
                *target ^= source;
            }
            Self::mix(block, &mut scratch, double);
        }
    }

    /// One pass of the derivation of PBKDF2, which scrypt uses before and after the mixing.
    pub fn stretch(&self, password: &[u8], salt: &[u8], output: &mut [u8]) {
        let size = self.prf.output_size();
        let mut block = alloc::vec![0; size];
        for (index, part) in output.chunks_mut(size).enumerate() {
            let mut message = Vec::with_capacity(salt.len() + 4);
            message.extend_from_slice(salt);
            message.extend_from_slice(&(index as u32 + 1).to_be_bytes());
            self.prf.compute(password, &message, &mut block);
            part.copy_from_slice(&block[..part.len()]);
        }
    }

    pub fn derive(&self, password: &[u8], salt: &[u8], output: &mut [u8]) -> Result<(), ScryptError> {
        if output.is_empty() {
            return Err(ScryptError::Length);
        }
        match self.request().map(|request| KDFProviders::derive(&request, &KDFProviderInputs::new(password, salt), output)).transpose()?.flatten() {
            Some(()) => Ok(()),
            None => {
                let length = 128 * self.block as usize;
                let mut blocks = alloc::vec![0; length * self.parallelism as usize];
                self.stretch(password, salt, &mut blocks);
                for block in blocks.chunks_exact_mut(length) {
                    self.walk(block);
                }
                self.stretch(password, &blocks, output);
                Ok(())
            }
        }
    }

    pub fn verify(&self, password: &[u8], salt: &[u8], expected: &[u8]) -> Result<(), ScryptError> {
        let mut output = alloc::vec![0; expected.len()];
        self.derive(password, salt, &mut output)?;
        let mut difference = 0;
        for (left, right) in output.iter().zip(expected) {
            difference |= left ^ right;
        }
        match difference {
            0 => Ok(()),
            _ => Err(ScryptError::Verification),
        }
    }
}
