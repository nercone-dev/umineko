use alloc::vec::Vec;
use crate::field::GF256;

/// A shortened Reed-Solomon code over the field of two hundred and fifty six elements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReedSolomon {
    field: GF256,
    blocks: usize,
    message: usize,
    corrections: usize,
    generator: Vec<u8>,
}

impl ReedSolomon {
    /// The code that corrects `corrections` errors in `blocks` symbols, of which `message` carry data.
    pub fn new(blocks: usize, message: usize, corrections: usize) -> Self {
        let field = GF256::new();
        let mut generator = alloc::vec![1];
        for root in 1..=2 * corrections {
            let mut next = alloc::vec![0; generator.len() + 1];
            for (index, coefficient) in generator.iter().enumerate() {
                next[index] ^= field.multiply(*coefficient, field.power(root));
                next[index + 1] ^= coefficient;
            }
            generator = next;
        }
        Self { field, blocks, message, corrections, generator }
    }

    pub fn field(&self) -> &GF256 {
        &self.field
    }

    pub fn generator(&self) -> &[u8] {
        &self.generator
    }

    pub fn parity(&self) -> usize {
        self.blocks - self.message
    }

    /// One codeword, which carries the message in its highest symbols.
    pub fn encode(&self, message: &[u8]) -> Vec<u8> {
        let mut codeword = alloc::vec![0; self.blocks];
        let parity = self.parity();
        for index in 0..self.message {
            let gate = message[self.message - 1 - index] ^ codeword[parity - 1];
            for position in (1..parity).rev() {
                codeword[position] = codeword[position - 1] ^ self.field.multiply(gate, self.generator[position]);
            }
            codeword[0] = self.field.multiply(gate, self.generator[0]);
        }
        codeword[parity..].copy_from_slice(&message[..self.message]);
        codeword
    }

    /// The values of the codeword at the roots of the generator, which vanish without errors.
    pub fn syndromes(&self, codeword: &[u8]) -> Vec<u8> {
        (0..2 * self.corrections)
            .map(|index| {
                let mut total = 0;
                for (position, symbol) in codeword.iter().enumerate() {
                    total ^= self.field.multiply(*symbol, self.field.power((index + 1) * position));
                }
                total
            })
            .collect()
    }

    /// The error locator polynomial, by the method of Berlekamp and Massey.
    pub fn locator(&self, syndromes: &[u8]) -> Vec<u8> {
        let mut locator = alloc::vec![1u8];
        let mut previous = alloc::vec![1u8];
        let (mut length, mut shift, mut discrepancy) = (0usize, 1usize, 1u8);
        for step in 0..syndromes.len() {
            let mut current = syndromes[step];
            for index in 1..=length {
                current ^= self.field.multiply(locator[index], syndromes[step - index]);
            }
            if current == 0 {
                shift += 1;
                continue;
            }
            let scale = self.field.multiply(current, self.field.inverse(discrepancy));
            let mut next = locator.clone();
            next.resize(next.len().max(previous.len() + shift), 0);
            for (index, coefficient) in previous.iter().enumerate() {
                next[index + shift] ^= self.field.multiply(scale, *coefficient);
            }
            match 2 * length <= step {
                true => {
                    previous = locator;
                    length = step + 1 - length;
                    discrepancy = current;
                    shift = 1;
                }
                false => shift += 1,
            }
            locator = next;
        }
        locator.truncate(self.corrections + 1);
        locator
    }

    /// The positions whose locator value is a root, which is where the errors sit.
    pub fn positions(&self, locator: &[u8]) -> Vec<usize> {
        (0..self.blocks).filter(|position| self.field.evaluate(locator, self.field.power(GF256::ORDER - position % GF256::ORDER)) == 0).collect()
    }

    /// The polynomial that carries the magnitudes of the errors.
    pub fn magnitudes(&self, locator: &[u8], syndromes: &[u8]) -> Vec<u8> {
        let mut values = alloc::vec![0; self.corrections + 1];
        values[0] = 1;
        for (index, value) in values.iter_mut().enumerate().skip(1) {
            *value = *locator.get(index).unwrap_or(&0);
        }
        values[1] ^= syndromes[0];
        for index in 2..=self.corrections {
            values[index] ^= syndromes[index - 1];
            for step in 1..index {
                values[index] ^= self.field.multiply(*locator.get(step).unwrap_or(&0), syndromes[index - step - 1]);
            }
        }
        values
    }

    /// The message inside a codeword, with up to `corrections` symbols put right.
    pub fn decode(&self, codeword: &[u8]) -> Vec<u8> {
        let mut codeword = codeword.to_vec();
        let syndromes = self.syndromes(&codeword);
        if syndromes.iter().all(|value| *value == 0) {
            return codeword[self.parity()..].to_vec();
        }
        let locator = self.locator(&syndromes);
        let positions = self.positions(&locator);
        let values = self.magnitudes(&locator, &syndromes);
        let mut locations = alloc::vec![0; self.corrections];
        for (slot, position) in positions.iter().enumerate().take(self.corrections) {
            locations[slot] = self.field.power(*position);
        }
        for (slot, position) in positions.iter().enumerate().take(self.corrections) {
            let inverse = self.field.inverse(locations[slot]);
            let mut numerator = 1;
            let mut power = 1;
            for value in values.iter().take(self.corrections + 1).skip(1) {
                power = self.field.multiply(power, inverse);
                numerator ^= self.field.multiply(power, *value);
            }
            let mut denominator = 1;
            for step in 1..self.corrections {
                denominator = self.field.multiply(denominator, 1 ^ self.field.multiply(inverse, locations[(slot + step) % self.corrections]));
            }
            codeword[*position] ^= self.field.multiply(numerator, self.field.inverse(denominator));
        }
        codeword[self.parity()..].to_vec()
    }
}

/// The Reed-Muller code of the first order over seven variables, repeated to fill one block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReedMuller {
    multiplicity: usize,
}

impl ReedMuller {
    pub const LENGTH: usize = 128;
    /// The columns of the generator, one mask for each of the five lowest message bits.
    pub const MASKS: [u32; 5] = [0xAAAA_AAAA, 0xCCCC_CCCC, 0xF0F0_F0F0, 0xFF00_FF00, 0xFFFF_0000];

    pub fn new(multiplicity: usize) -> Self {
        Self { multiplicity }
    }

    pub fn multiplicity(&self) -> usize {
        self.multiplicity
    }

    pub fn spread(value: u8) -> u32 {
        ((value & 1) as u32).wrapping_neg()
    }

    /// The hundred and twenty eight bit word of one message byte, as four words of thirty two bits.
    pub fn word(message: u8) -> [u32; 4] {
        let mut first = Self::spread(message >> 7);
        for (index, mask) in Self::MASKS.into_iter().enumerate() {
            first ^= Self::spread(message >> index) & mask;
        }
        let mut word = [0; 4];
        word[0] = first;
        first ^= Self::spread(message >> 5);
        word[1] = first;
        first ^= Self::spread(message >> 6);
        word[3] = first;
        first ^= Self::spread(message >> 5);
        word[2] = first;
        word
    }

    pub fn encode(&self, message: &[u8]) -> Vec<u8> {
        let mut codeword = Vec::with_capacity(message.len() * self.multiplicity * 16);
        for symbol in message {
            let word = Self::word(*symbol);
            for _ in 0..self.multiplicity {
                for value in word {
                    codeword.extend_from_slice(&value.to_le_bytes());
                }
            }
        }
        codeword
    }

    /// The sums of the repeated copies of one word, one entry for each of its bits.
    pub fn gather(&self, block: &[u8]) -> [i32; Self::LENGTH] {
        let mut sums = [0; Self::LENGTH];
        for copy in 0..self.multiplicity {
            for (position, sum) in sums.iter_mut().enumerate() {
                let offset = copy * 16 + position / 8;
                *sum += ((block[offset] >> (position % 8)) & 1) as i32;
            }
        }
        sums
    }

    /// The Walsh-Hadamard transform of one gathered word, over seven passes.
    pub fn transform(sums: &[i32; Self::LENGTH]) -> [i32; Self::LENGTH] {
        let mut source = *sums;
        let mut target = [0; Self::LENGTH];
        for _ in 0..7 {
            for index in 0..Self::LENGTH / 2 {
                target[index] = source[index * 2] + source[index * 2 + 1];
                target[index + Self::LENGTH / 2] = source[index * 2] - source[index * 2 + 1];
            }
            core::mem::swap(&mut source, &mut target);
        }
        source
    }

    /// The message byte behind the highest peak of a transform.
    pub fn peak(transform: &[i32; Self::LENGTH]) -> u8 {
        let (mut value, mut position, mut height) = (0, 0, 0);
        for (index, entry) in transform.iter().enumerate() {
            if entry.abs() > height {
                height = entry.abs();
                value = *entry;
                position = index;
            }
        }
        (position ^ (Self::LENGTH * (value > 0) as usize)) as u8
    }

    pub fn decode(&self, codeword: &[u8]) -> Vec<u8> {
        codeword
            .chunks_exact(self.multiplicity * 16)
            .map(|block| {
                let sums = self.gather(block);
                let mut transform = Self::transform(&sums);
                transform[0] -= 64 * self.multiplicity as i32;
                Self::peak(&transform)
            })
            .collect()
    }
}
