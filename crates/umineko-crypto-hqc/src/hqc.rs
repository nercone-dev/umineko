use alloc::vec::Vec;
use core::fmt;
use crate::code::{ReedMuller, ReedSolomon};
use crate::errors::HQCError;

use umineko_hash_sha::{SHA3_256, SHA3_512, SHAKE256};
use umineko_helpers::provider::{ExchangeProviderRequest, ExchangeProviders};

/// A reader over the extendable output that every value of the scheme is drawn from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HQCStream {
    seed: Vec<u8>,
    buffer: Vec<u8>,
    position: usize,
}

impl HQCStream {
    pub const BLOCK: usize = 1024;

    pub fn new(seed: &[u8], domain: u8) -> Self {
        let mut input = seed.to_vec();
        input.push(domain);
        Self { seed: input, buffer: Vec::new(), position: 0 }
    }

    /// The next `length` bytes, squeezing a longer output whenever the reader runs out.
    pub fn take(&mut self, length: usize) -> &[u8] {
        while self.position + length > self.buffer.len() {
            let wanted = (self.buffer.len() + length).max(Self::BLOCK) * 2;
            self.buffer = alloc::vec![0; wanted];
            SHAKE256::digest(&self.seed, &mut self.buffer);
        }
        self.position += length;
        &self.buffer[self.position - length..self.position]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HQC {
    V128,
    V192,
    V256,
}

impl HQC {
    pub const ALL: [Self; 3] = [Self::V128, Self::V192, Self::V256];
    pub const SEED_SIZE: usize = 32;
    pub const SALT_SIZE: usize = 16;
    pub const SECRET_SIZE: usize = 32;
    /// The byte that separates the extendable output of the scheme from its digests.
    pub const XOF_DOMAIN: u8 = 1;
    pub const SECRET_DOMAIN: u8 = 0;
    pub const KEY_DOMAIN: u8 = 1;
    pub const SEED_DOMAIN: u8 = 2;
    pub const REJECT_DOMAIN: u8 = 3;

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V128 => "HQC-128",
            Self::V192 => "HQC-192",
            Self::V256 => "HQC-256",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "HQC-128" => Some(Self::V128),
            "HQC-192" => Some(Self::V192),
            "HQC-256" => Some(Self::V256),
            _ => None,
        }
    }

    /// The length of the cyclic code, in bits.
    pub fn length(&self) -> usize {
        match self {
            Self::V128 => 17669,
            Self::V192 => 35851,
            Self::V256 => 57637,
        }
    }

    /// The number of symbols of the outer code.
    pub fn blocks(&self) -> usize {
        match self {
            Self::V128 => 46,
            Self::V192 => 56,
            Self::V256 => 90,
        }
    }

    /// The length of one word of the inner code, in bits.
    pub fn block_length(&self) -> usize {
        match self {
            Self::V128 => 384,
            Self::V192 | Self::V256 => 640,
        }
    }

    pub fn multiplicity(&self) -> usize {
        self.block_length() / ReedMuller::LENGTH
    }

    pub fn message_size(&self) -> usize {
        match self {
            Self::V128 => 16,
            Self::V192 => 24,
            Self::V256 => 32,
        }
    }

    pub fn corrections(&self) -> usize {
        match self {
            Self::V128 => 15,
            Self::V192 => 16,
            Self::V256 => 29,
        }
    }

    /// The weight of the two halves of the private key.
    pub fn weight(&self) -> usize {
        match self {
            Self::V128 => 66,
            Self::V192 => 100,
            Self::V256 => 131,
        }
    }

    /// The weight of the three vectors that one ciphertext draws.
    pub fn error_weight(&self) -> usize {
        match self {
            Self::V128 => 75,
            Self::V192 => 114,
            Self::V256 => 149,
        }
    }

    /// The highest draw that the rejection sampler accepts.
    pub fn threshold(&self) -> u32 {
        match self {
            Self::V128 => 16_767_881,
            Self::V192 => 16_742_417,
            Self::V256 => 16_772_367,
        }
    }

    /// The multiplier that reduces one draw without a division.
    pub fn factor(&self) -> u64 {
        match self {
            Self::V128 => 243_079,
            Self::V192 => 119_800,
            Self::V256 => 74_517,
        }
    }

    pub fn vector_size(&self) -> usize {
        self.length().div_ceil(8)
    }

    pub fn code_size(&self) -> usize {
        (self.blocks() * self.block_length()).div_ceil(8)
    }

    pub fn public_key_size(&self) -> usize {
        Self::SEED_SIZE + self.vector_size()
    }

    pub fn private_key_size(&self) -> usize {
        self.public_key_size() + Self::SEED_SIZE + self.message_size() + Self::SEED_SIZE
    }

    pub fn ciphertext_size(&self) -> usize {
        self.vector_size() + self.code_size() + Self::SALT_SIZE
    }

    pub fn shared_secret_size(&self) -> usize {
        Self::SECRET_SIZE
    }

    pub fn seed_size(&self) -> usize {
        Self::SEED_SIZE
    }

    pub fn solomon(&self) -> ReedSolomon {
        ReedSolomon::new(self.blocks(), self.message_size(), self.corrections())
    }

    pub fn muller(&self) -> ReedMuller {
        ReedMuller::new(self.multiplicity())
    }

    pub fn stream(seed: &[u8]) -> HQCStream {
        HQCStream::new(seed, Self::XOF_DOMAIN)
    }

    /// The two seeds of one key pair.
    pub fn seeds(seed: &[u8]) -> [u8; 64] {
        let mut input = seed.to_vec();
        input.push(Self::SEED_DOMAIN);
        SHA3_512::digest(&input)
    }

    pub fn fingerprint(key: &[u8]) -> [u8; 32] {
        let mut input = key.to_vec();
        input.push(Self::KEY_DOMAIN);
        SHA3_256::digest(&input)
    }

    /// The shared secret and the seed of one ciphertext.
    pub fn couple(fingerprint: &[u8], message: &[u8], salt: &[u8]) -> [u8; 64] {
        let mut input = fingerprint.to_vec();
        input.extend_from_slice(message);
        input.extend_from_slice(salt);
        input.push(Self::SECRET_DOMAIN);
        SHA3_512::digest(&input)
    }

    /// The shared secret of a ciphertext that does not open, which the private key alone decides.
    pub fn rejection(fingerprint: &[u8], secret: &[u8], ciphertext: &[u8]) -> [u8; 32] {
        let mut input = fingerprint.to_vec();
        input.extend_from_slice(secret);
        input.extend_from_slice(ciphertext);
        input.push(Self::REJECT_DOMAIN);
        SHA3_256::digest(&input)
    }

    pub fn mask(&self, vector: &mut [u8]) {
        let rest = self.length() % 8;
        if rest != 0 {
            vector[self.vector_size() - 1] &= (1 << rest) - 1;
        }
    }

    /// One vector of the whole length, drawn without any weight in mind.
    pub fn random(&self, stream: &mut HQCStream) -> Vec<u8> {
        let mut vector = stream.take(self.vector_size()).to_vec();
        self.mask(&mut vector);
        vector
    }

    /// The support of one fixed weight vector, drawn by rejection as the key pair asks.
    pub fn support(&self, stream: &mut HQCStream, weight: usize) -> Vec<usize> {
        let mut support = Vec::with_capacity(weight);
        while support.len() < weight {
            let bytes = stream.take(3);
            let draw = bytes[0] as u32 | ((bytes[1] as u32) << 8) | ((bytes[2] as u32) << 16);
            if draw >= self.threshold() {
                continue;
            }
            let quotient = (draw as u64 * self.factor()) >> 32;
            let mut position = draw.wrapping_sub((quotient * self.length() as u64) as u32) as usize;
            if position >= self.length() {
                position -= self.length();
            }
            if !support.contains(&position) {
                support.push(position);
            }
        }
        support
    }

    /// The support of one fixed weight vector, drawn by shuffling as a ciphertext asks.
    pub fn shuffle(&self, stream: &mut HQCStream, weight: usize) -> Vec<usize> {
        let bytes = stream.take(weight * 4).to_vec();
        let mut support: Vec<usize> = (0..weight)
            .map(|index| {
                let draw = u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap_or([0; 4]));
                index + ((draw as u64 * (self.length() - index) as u64) >> 32) as usize
            })
            .collect();
        for index in (0..weight).rev() {
            let duplicate = support[index + 1..].contains(&support[index]);
            if duplicate {
                support[index] = index;
            }
        }
        support
    }

    pub fn spread(&self, support: &[usize]) -> Vec<u8> {
        let mut vector = alloc::vec![0; self.vector_size()];
        for position in support {
            vector[position / 8] |= 1 << (position % 8);
        }
        vector
    }

    pub fn add(left: &[u8], right: &[u8]) -> Vec<u8> {
        left.iter().zip(right).map(|(first, second)| first ^ second).collect()
    }

    /// The product of a sparse vector and a dense one, over the ring of the cyclic code.
    pub fn multiply(&self, support: &[usize], dense: &[u8]) -> Vec<u8> {
        let (length, size) = (self.length(), self.vector_size());
        let mut doubled = alloc::vec![0; size * 2 + 2];
        doubled[..size].copy_from_slice(dense);
        let (whole, bit) = (length / 8, length % 8);
        for (index, byte) in dense.iter().enumerate() {
            doubled[whole + index] |= byte << bit;
            if bit != 0 {
                doubled[whole + index + 1] |= byte >> (8 - bit);
            }
        }
        let mut product = alloc::vec![0; size];
        for shift in support {
            let start = length - shift;
            let (offset, part) = (start / 8, start % 8);
            for (index, target) in product.iter_mut().enumerate() {
                let low = doubled[offset + index] >> part;
                let high = match part {
                    0 => 0,
                    part => doubled[offset + index + 1] << (8 - part),
                };
                *target ^= low | high;
            }
        }
        self.mask(&mut product);
        product
    }

    pub fn truncate(&self, vector: &[u8]) -> Vec<u8> {
        let mut truncated = vector[..self.code_size()].to_vec();
        let rest = (self.blocks() * self.block_length()) % 8;
        if rest != 0 {
            truncated[self.code_size() - 1] &= (1 << rest) - 1;
        }
        truncated
    }

    pub fn encode(&self, message: &[u8]) -> Vec<u8> {
        self.muller().encode(&self.solomon().encode(message))
    }

    pub fn decode(&self, codeword: &[u8]) -> Vec<u8> {
        self.solomon().decode(&self.muller().decode(codeword))
    }

    /// The key pair of the encryption behind the scheme, from one seed.
    pub fn keys(&self, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let seeds = Self::seeds(seed);
        let (private, public) = seeds.split_at(Self::SEED_SIZE);
        let mut stream = Self::stream(private);
        let key = self.support(&mut stream, self.weight());
        let offset = self.support(&mut stream, self.weight());
        let parameter = self.random(&mut Self::stream(public));
        let value = Self::add(&self.spread(&offset), &self.multiply(&key, &parameter));
        let mut encryption = public.to_vec();
        encryption.extend_from_slice(&value);
        (encryption, private.to_vec())
    }

    /// The ciphertext of the encryption behind the scheme, over a message and a seed.
    pub fn seal(&self, encryption: &[u8], message: &[u8], seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (public, value) = encryption.split_at(Self::SEED_SIZE);
        let parameter = self.random(&mut Self::stream(public));
        let mut stream = Self::stream(seed);
        let mask = self.shuffle(&mut stream, self.error_weight());
        let error = self.shuffle(&mut stream, self.error_weight());
        let offset = self.shuffle(&mut stream, self.error_weight());
        let first = Self::add(&self.multiply(&mask, &parameter), &self.spread(&offset));
        let second = Self::add(&self.truncate(&Self::add(&self.multiply(&mask, value), &self.spread(&error))), &self.encode(message));
        (first, second)
    }

    /// The message inside a ciphertext of the encryption behind the scheme.
    pub fn open(&self, decryption: &[u8], first: &[u8], second: &[u8]) -> Vec<u8> {
        let key = self.support(&mut Self::stream(decryption), self.weight());
        self.decode(&Self::add(second, &self.truncate(&self.multiply(&key, first))))
    }
}

impl fmt::Display for HQC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl HQC {
    pub fn request(&self) -> ExchangeProviderRequest<'static> {
        ExchangeProviderRequest::new(self.as_str())
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(HQCPrivateKey, HQCPublicKey), HQCError> {
        match ExchangeProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((HQCPrivateKey { variant: *self, key: private }, HQCPublicKey { variant: *self, key: public })),
            None => {
                if seed.len() < self.seed_size() {
                    return Err(HQCError::Seed);
                }
                let seed = &seed[..Self::SEED_SIZE];
                let mut stream = Self::stream(seed);
                let inner = stream.take(Self::SEED_SIZE).to_vec();
                let secret = stream.take(self.message_size()).to_vec();
                let (encryption, decryption) = self.keys(&inner);
                let mut key = encryption.clone();
                key.extend_from_slice(&decryption);
                key.extend_from_slice(&secret);
                key.extend_from_slice(seed);
                Ok((HQCPrivateKey { variant: *self, key }, HQCPublicKey { variant: *self, key: encryption }))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HQCPrivateKey {
    variant: HQC,
    key: Vec<u8>,
}

impl HQCPrivateKey {
    pub fn decode(variant: HQC, data: &[u8]) -> Result<Self, HQCError> {
        match data.len() == variant.private_key_size() {
            true => Ok(Self { variant, key: data.to_vec() }),
            false => Err(HQCError::Encoding),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> HQC {
        self.variant
    }

    pub fn public_key(&self) -> HQCPublicKey {
        let request = self.variant.request();
        match ExchangeProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.public_key(&request, &self.key)) {
            Some(key) => HQCPublicKey { variant: self.variant, key },
            None => HQCPublicKey { variant: self.variant, key: self.key[..self.variant.public_key_size()].to_vec() },
        }
    }

    pub fn decapsulate(&self, ciphertext: &HQCCiphertext) -> Result<HQCSharedSecret, HQCError> {
        if ciphertext.variant != self.variant {
            return Err(HQCError::Variant);
        }
        match ExchangeProviders::decapsulate(&self.variant.request(), &self.key, &ciphertext.ciphertext)? {
            Some(secret) => Ok(HQCSharedSecret { secret }),
            None => {
                let variant = self.variant;
                let encryption = &self.key[..variant.public_key_size()];
                let decryption = &self.key[variant.public_key_size()..variant.public_key_size() + HQC::SEED_SIZE];
                let rejection = &self.key[variant.public_key_size() + HQC::SEED_SIZE..variant.public_key_size() + HQC::SEED_SIZE + variant.message_size()];
                let (first, rest) = ciphertext.ciphertext.split_at(variant.vector_size());
                let (second, salt) = rest.split_at(variant.code_size());
                let message = variant.open(decryption, first, second);
                let fingerprint = HQC::fingerprint(encryption);
                let coupled = HQC::couple(&fingerprint, &message, salt);
                let (secret, seed) = coupled.split_at(HQC::SECRET_SIZE);
                let (produced, other) = variant.seal(encryption, &message, seed);
                let fallback = HQC::rejection(&fingerprint, rejection, &ciphertext.ciphertext[..variant.vector_size() + variant.code_size() + HQC::SALT_SIZE]);
                let mut difference = 0u8;
                for (left, right) in produced.iter().chain(&other).zip(first.iter().chain(second)) {
                    difference |= left ^ right;
                }
                let mask = ((difference != 0) as u8).wrapping_neg();
                Ok(HQCSharedSecret { secret: secret.iter().zip(&fallback).map(|(right, wrong)| (right & !mask) | (wrong & mask)).collect() })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HQCPublicKey {
    variant: HQC,
    key: Vec<u8>,
}

impl HQCPublicKey {
    pub fn decode(variant: HQC, data: &[u8]) -> Result<Self, HQCError> {
        match data.len() == variant.public_key_size() {
            true => Ok(Self { variant, key: data.to_vec() }),
            false => Err(HQCError::Encoding),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> HQC {
        self.variant
    }

    pub fn encapsulate(&self, seed: &[u8]) -> Result<(HQCCiphertext, HQCSharedSecret), HQCError> {
        match ExchangeProviders::encapsulate(&self.variant.request().with_seed(seed), &self.key)? {
            Some((ciphertext, secret)) => Ok((HQCCiphertext { variant: self.variant, ciphertext }, HQCSharedSecret { secret })),
            None => {
                let variant = self.variant;
                if seed.len() < variant.message_size() + HQC::SALT_SIZE {
                    return Err(HQCError::Seed);
                }
                let (message, salt) = seed.split_at(variant.message_size());
                let salt = &salt[..HQC::SALT_SIZE];
                let fingerprint = HQC::fingerprint(&self.key);
                let coupled = HQC::couple(&fingerprint, message, salt);
                let (secret, inner) = coupled.split_at(HQC::SECRET_SIZE);
                let (first, second) = variant.seal(&self.key, message, inner);
                let mut ciphertext = first;
                ciphertext.extend_from_slice(&second);
                ciphertext.extend_from_slice(salt);
                Ok((HQCCiphertext { variant, ciphertext }, HQCSharedSecret { secret: secret.to_vec() }))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HQCCiphertext {
    variant: HQC,
    ciphertext: Vec<u8>,
}

impl HQCCiphertext {
    pub fn decode(variant: HQC, data: &[u8]) -> Result<Self, HQCError> {
        match data.len() == variant.ciphertext_size() {
            true => Ok(Self { variant, ciphertext: data.to_vec() }),
            false => Err(HQCError::Encoding),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    pub fn variant(&self) -> HQC {
        self.variant
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HQCSharedSecret {
    secret: Vec<u8>,
}

impl HQCSharedSecret {
    pub fn as_slice(&self) -> &[u8] {
        &self.secret
    }

    pub fn len(&self) -> usize {
        self.secret.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
