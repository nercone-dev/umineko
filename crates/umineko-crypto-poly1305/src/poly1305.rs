use crate::errors::Poly1305Error;

use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug)]
pub struct Poly1305 {
    accumulator: [u32; 5],
    r: [u32; 5],
    s: [u32; 4],
    buffer: [u8; 16],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl Poly1305 {
    pub const NAME: &'static str = "Poly1305";
    pub const KEY_SIZE: usize = 32;
    pub const TAG_SIZE: usize = 16;
    pub const BLOCK_SIZE: usize = 16;
    pub const LIMB_BITS: u32 = 26;
    pub const LIMB_MASK: u32 = (1 << Self::LIMB_BITS) - 1;
    /// The bits of the key that the clamping of the multiplier keeps.
    pub const CLAMP: [u32; 5] = [0x03FF_FFFF, 0x03FF_FF03, 0x03FF_C0FF, 0x03F0_3FFF, 0x000F_FFFF];

    pub fn new(key: &[u8; 32]) -> Self {
        match HashProviders::backend(&Self::request(key)) {
            ProviderBackend::Builtin => Self::builtin(key),
            backend => Self { accumulator: [0; 5], r: [0; 5], s: [0; 4], buffer: [0; 16], length: 0, backend },
        }
    }

    pub fn builtin(key: &[u8; 32]) -> Self {
        let mut words = [0u32; 4];
        for (word, chunk) in words.iter_mut().zip(key[..16].chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let r = [
            words[0] & Self::CLAMP[0],
            ((words[0] >> 26) | (words[1] << 6)) & Self::CLAMP[1],
            ((words[1] >> 20) | (words[2] << 12)) & Self::CLAMP[2],
            ((words[2] >> 14) | (words[3] << 18)) & Self::CLAMP[3],
            (words[3] >> 8) & Self::CLAMP[4],
        ];
        let mut s = [0u32; 4];
        for (word, chunk) in s.iter_mut().zip(key[16..].chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        Self { accumulator: [0; 5], r, s, buffer: [0; 16], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request(key: &[u8; 32]) -> HashProviderRequest<'_> {
        HashProviderRequest::new(Self::NAME).with_key(key)
    }

    /// One block added to the accumulator and multiplied by the clamped key, modulo two to the hundred and thirtieth less five.
    pub fn absorb(accumulator: &mut [u32; 5], r: &[u32; 5], block: &[u8], last: bool) {
        let mut words = [0u32; 4];
        let mut padded = [0u8; 16];
        padded[..block.len()].copy_from_slice(block);
        if last && block.len() < Self::BLOCK_SIZE {
            padded[block.len()] = 1;
        }
        for (word, chunk) in words.iter_mut().zip(padded.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let high = match last && block.len() < Self::BLOCK_SIZE {
            true => 0,
            false => 1 << 24,
        };
        accumulator[0] += words[0] & Self::LIMB_MASK;
        accumulator[1] += ((words[0] >> 26) | (words[1] << 6)) & Self::LIMB_MASK;
        accumulator[2] += ((words[1] >> 20) | (words[2] << 12)) & Self::LIMB_MASK;
        accumulator[3] += ((words[2] >> 14) | (words[3] << 18)) & Self::LIMB_MASK;
        accumulator[4] += (words[3] >> 8) | high;
        let folded: [u64; 5] = core::array::from_fn(|index| r[index] as u64 * 5);
        let mut products = [0u64; 5];
        for (index, product) in products.iter_mut().enumerate() {
            for (offset, value) in accumulator.iter().enumerate() {
                *product += *value as u64 * match offset <= index {
                    true => r[index - offset] as u64,
                    false => folded[5 + index - offset],
                };
            }
        }
        let mut carry = 0u64;
        for (value, product) in accumulator.iter_mut().zip(products) {
            let sum = product + carry;
            *value = sum as u32 & Self::LIMB_MASK;
            carry = sum >> Self::LIMB_BITS;
        }
        accumulator[0] += carry as u32 * 5;
        accumulator[1] += accumulator[0] >> Self::LIMB_BITS;
        accumulator[0] &= Self::LIMB_MASK;
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => {
                let mut data = data;
                while !data.is_empty() {
                    if self.length == Self::BLOCK_SIZE {
                        let block = self.buffer;
                        Self::absorb(&mut self.accumulator, &self.r, &block, false);
                        self.length = 0;
                    }
                    let taken = (Self::BLOCK_SIZE - self.length).min(data.len());
                    self.buffer[self.length..self.length + taken].copy_from_slice(&data[..taken]);
                    self.length += taken;
                    data = &data[taken..];
                }
            }
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> [u8; 16] {
        match &self.backend {
            ProviderBackend::Builtin => Self::squeeze(&self.accumulator, &self.r, &self.s, &self.buffer[..self.length]),
            ProviderBackend::Handle { provider, handle } => {
                let mut tag = [0; 16];
                provider.finalize(*handle, &mut tag);
                tag
            }
        }
    }

    /// The accumulator reduced, cut to a hundred and twenty eight bits and offset by the second half of the key.
    pub fn squeeze(accumulator: &[u32; 5], r: &[u32; 5], s: &[u32; 4], rest: &[u8]) -> [u8; 16] {
        let mut accumulator = *accumulator;
        if !rest.is_empty() {
            Self::absorb(&mut accumulator, r, rest, true);
        }
        let mut carry = 0;
        for value in accumulator.iter_mut().skip(1) {
            *value += carry;
            carry = *value >> Self::LIMB_BITS;
            *value &= Self::LIMB_MASK;
        }
        accumulator[0] += carry * 5;
        accumulator[1] += accumulator[0] >> Self::LIMB_BITS;
        accumulator[0] &= Self::LIMB_MASK;
        let mut reduced = [0u32; 5];
        let mut carry = 5;
        for (value, current) in reduced.iter_mut().zip(accumulator) {
            *value = current + carry;
            carry = *value >> Self::LIMB_BITS;
            *value &= Self::LIMB_MASK;
        }
        reduced[4] = reduced[4].wrapping_sub(1 << Self::LIMB_BITS);
        let mask = (reduced[4] >> 31).wrapping_sub(1);
        for (value, current) in accumulator.iter_mut().zip(reduced) {
            *value = (*value & !mask) | (current & mask);
        }
        let words = [
            accumulator[0] | (accumulator[1] << 26),
            (accumulator[1] >> 6) | (accumulator[2] << 20),
            (accumulator[2] >> 12) | (accumulator[3] << 14),
            (accumulator[3] >> 18) | (accumulator[4] << 8),
        ];
        let mut tag = [0; 16];
        let mut carry = 0u64;
        for (chunk, (word, offset)) in tag.chunks_exact_mut(4).zip(words.into_iter().zip(s)) {
            let sum = word as u64 + *offset as u64 + carry;
            chunk.copy_from_slice(&(sum as u32).to_le_bytes());
            carry = sum >> 32;
        }
        tag
    }

    pub fn verify(self, tag: &[u8; 16]) -> Result<(), Poly1305Error> {
        let computed = self.finalize();
        let mut difference = 0;
        for (left, right) in computed.iter().zip(tag) {
            difference |= left ^ right;
        }
        match difference {
            0 => Ok(()),
            _ => Err(Poly1305Error::Authentication),
        }
    }

    pub fn tag(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
        let mut tag = [0; 16];
        match HashProviders::digest(&Self::request(key), data, &mut tag) {
            Some(_) => tag,
            None => {
                let mut mac = Self::builtin(key);
                mac.update(data);
                mac.finalize()
            }
        }
    }
}

impl Clone for Poly1305 {
    fn clone(&self) -> Self {
        Self { accumulator: self.accumulator, r: self.r, s: self.s, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}
