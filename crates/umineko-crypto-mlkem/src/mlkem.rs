use alloc::vec::Vec;
use core::fmt;
use crate::errors::MLKEMError;

use umineko_hash_sha::{SHA3_256, SHA3_512, SHAKE128, SHAKE256};
use umineko_helpers::provider::{ExchangeProviderRequest, ExchangeProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MLKEM {
    V512,
    V768,
    V1024,
}

impl MLKEM {
    pub const ALL: [Self; 3] = [Self::V512, Self::V768, Self::V1024];
    pub const MODULUS: u16 = 3329;
    pub const DEGREE: usize = 256;
    /// The inverse of a hundred and twenty eight, which closes the inverse transform.
    pub const SCALE: u16 = 3303;
    pub const SEED_SIZE: usize = 32;
    pub const ZETAS: [u16; 128] = [
        1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746,
        296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
        289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915,
        2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
        17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
        1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641,
        1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594,
        2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
    ];
    pub const GAMMAS: [u16; 128] = [
        17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229,
        1409, 1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279,
        1703, 1626, 1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642,
        939, 2390, 2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992, 268, 3061, 641, 2688,
        1584, 1745, 2298, 1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684,
        1063, 2266, 319, 3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735,
        2804, 525, 1092, 2237, 403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443,
        1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V512 => "ML-KEM-512",
            Self::V768 => "ML-KEM-768",
            Self::V1024 => "ML-KEM-1024",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ML-KEM-512" => Some(Self::V512),
            "ML-KEM-768" => Some(Self::V768),
            "ML-KEM-1024" => Some(Self::V1024),
            _ => None,
        }
    }

    /// The number of polynomials in one vector, which sets the strength of the variant.
    pub fn rank(&self) -> usize {
        match self {
            Self::V512 => 2,
            Self::V768 => 3,
            Self::V1024 => 4,
        }
    }

    pub fn secret_noise(&self) -> usize {
        match self {
            Self::V512 => 3,
            Self::V768 | Self::V1024 => 2,
        }
    }

    pub fn error_noise(&self) -> usize {
        2
    }

    pub fn vector_bits(&self) -> usize {
        match self {
            Self::V512 | Self::V768 => 10,
            Self::V1024 => 11,
        }
    }

    pub fn constant_bits(&self) -> usize {
        match self {
            Self::V512 | Self::V768 => 4,
            Self::V1024 => 5,
        }
    }

    pub fn public_key_size(&self) -> usize {
        384 * self.rank() + 32
    }

    pub fn private_key_size(&self) -> usize {
        768 * self.rank() + 96
    }

    pub fn ciphertext_size(&self) -> usize {
        32 * (self.vector_bits() * self.rank() + self.constant_bits())
    }

    pub fn shared_secret_size(&self) -> usize {
        32
    }

    pub fn seed_size(&self) -> usize {
        64
    }

    pub fn reduce(value: u32) -> u16 {
        (value % Self::MODULUS as u32) as u16
    }

    pub fn add(left: u16, right: u16) -> u16 {
        Self::reduce(left as u32 + right as u32)
    }

    pub fn subtract(left: u16, right: u16) -> u16 {
        Self::reduce(left as u32 + Self::MODULUS as u32 - right as u32)
    }

    pub fn multiply(left: u16, right: u16) -> u16 {
        Self::reduce(left as u32 * right as u32)
    }

    /// The number theoretic transform, which turns a polynomial into a hundred and twenty eight pairs.
    pub fn transform(polynomial: &mut [u16; Self::DEGREE]) {
        let mut index = 1;
        let mut length = 128;
        while length >= 2 {
            for start in (0..Self::DEGREE).step_by(length * 2) {
                let zeta = Self::ZETAS[index];
                index += 1;
                for position in start..start + length {
                    let step = Self::multiply(zeta, polynomial[position + length]);
                    polynomial[position + length] = Self::subtract(polynomial[position], step);
                    polynomial[position] = Self::add(polynomial[position], step);
                }
            }
            length /= 2;
        }
    }

    pub fn untransform(polynomial: &mut [u16; Self::DEGREE]) {
        let mut index = 127;
        let mut length = 2;
        while length <= 128 {
            for start in (0..Self::DEGREE).step_by(length * 2) {
                let zeta = Self::ZETAS[index];
                index = index.saturating_sub(1);
                for position in start..start + length {
                    let step = polynomial[position];
                    polynomial[position] = Self::add(step, polynomial[position + length]);
                    polynomial[position + length] = Self::multiply(zeta, Self::subtract(polynomial[position + length], step));
                }
            }
            length *= 2;
        }
        for value in polynomial.iter_mut() {
            *value = Self::multiply(*value, Self::SCALE);
        }
    }

    /// The product of two transformed polynomials, taken pair by pair over the quadratic factors.
    pub fn product(left: &[u16; Self::DEGREE], right: &[u16; Self::DEGREE]) -> [u16; Self::DEGREE] {
        let mut product = [0; Self::DEGREE];
        for index in 0..Self::DEGREE / 2 {
            let (first, second) = (left[index * 2], left[index * 2 + 1]);
            let (third, fourth) = (right[index * 2], right[index * 2 + 1]);
            product[index * 2] = Self::add(Self::multiply(first, third), Self::multiply(Self::multiply(second, fourth), Self::GAMMAS[index]));
            product[index * 2 + 1] = Self::add(Self::multiply(first, fourth), Self::multiply(second, third));
        }
        product
    }

    pub fn combine(left: &[u16; Self::DEGREE], right: &[u16; Self::DEGREE]) -> [u16; Self::DEGREE] {
        core::array::from_fn(|index| Self::add(left[index], right[index]))
    }

    pub fn separate(left: &[u16; Self::DEGREE], right: &[u16; Self::DEGREE]) -> [u16; Self::DEGREE] {
        core::array::from_fn(|index| Self::subtract(left[index], right[index]))
    }

    pub fn compress(value: u16, bits: usize) -> u16 {
        let scaled = ((value as u32) << bits) + Self::MODULUS as u32 / 2;
        ((scaled / Self::MODULUS as u32) as u16) & ((1 << bits) - 1)
    }

    pub fn decompress(value: u16, bits: usize) -> u16 {
        ((value as u32 * Self::MODULUS as u32 + (1 << (bits - 1))) >> bits) as u16
    }

    /// One polynomial as `bits` bits for each coefficient, in the little endian bit order.
    pub fn encode(polynomial: &[u16; Self::DEGREE], bits: usize) -> Vec<u8> {
        let mut bytes = alloc::vec![0; Self::DEGREE * bits / 8];
        for (index, value) in polynomial.iter().enumerate() {
            for bit in 0..bits {
                let position = index * bits + bit;
                bytes[position / 8] |= (((value >> bit) & 1) as u8) << (position % 8);
            }
        }
        bytes
    }

    pub fn decode(bytes: &[u8], bits: usize) -> [u16; Self::DEGREE] {
        let mut polynomial = [0; Self::DEGREE];
        for (index, value) in polynomial.iter_mut().enumerate() {
            for bit in 0..bits {
                let position = index * bits + bit;
                *value |= (((bytes[position / 8] >> (position % 8)) & 1) as u16) << bit;
            }
            if bits == 12 {
                *value %= Self::MODULUS;
            }
        }
        polynomial
    }

    /// One polynomial drawn from the extendable output of a seed and two indices.
    pub fn sample(seed: &[u8], first: u8, second: u8) -> [u16; Self::DEGREE] {
        let mut input = seed.to_vec();
        input.push(first);
        input.push(second);
        let mut polynomial = [0; Self::DEGREE];
        let mut length = 512;
        loop {
            let mut stream = alloc::vec![0; length];
            SHAKE128::digest(&input, &mut stream);
            let mut filled = 0;
            for chunk in stream.chunks_exact(3) {
                let low = chunk[0] as u16 | ((chunk[1] as u16 & 0x0F) << 8);
                let high = (chunk[1] as u16 >> 4) | ((chunk[2] as u16) << 4);
                for candidate in [low, high] {
                    if candidate < Self::MODULUS && filled < Self::DEGREE {
                        polynomial[filled] = candidate;
                        filled += 1;
                    }
                }
            }
            if filled == Self::DEGREE {
                return polynomial;
            }
            length *= 2;
        }
    }

    /// One polynomial of small coefficients, from the difference of two sums of bits.
    pub fn noise(&self, seed: &[u8], nonce: u8, width: usize) -> [u16; Self::DEGREE] {
        let mut input = seed.to_vec();
        input.push(nonce);
        let mut stream = alloc::vec![0; 64 * width];
        SHAKE256::digest(&input, &mut stream);
        let bit = |position: usize| ((stream[position / 8] >> (position % 8)) & 1) as u16;
        let mut polynomial = [0; Self::DEGREE];
        for (index, value) in polynomial.iter_mut().enumerate() {
            let mut left = 0;
            let mut right = 0;
            for step in 0..width {
                left += bit(index * width * 2 + step);
                right += bit(index * width * 2 + width + step);
            }
            *value = Self::subtract(left, right);
        }
        polynomial
    }

    /// The matrix of the public parameters, which the seed alone decides.
    pub fn matrix(&self, seed: &[u8], transposed: bool) -> Vec<Vec<[u16; Self::DEGREE]>> {
        (0..self.rank())
            .map(|row| {
                (0..self.rank())
                    .map(|column| match transposed {
                        true => Self::sample(seed, row as u8, column as u8),
                        false => Self::sample(seed, column as u8, row as u8),
                    })
                    .collect()
            })
            .collect()
    }

    pub fn vector(&self, polynomials: &[[u16; Self::DEGREE]], bits: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(polynomials.len() * 32 * bits);
        for polynomial in polynomials {
            bytes.extend_from_slice(&Self::encode(polynomial, bits));
        }
        bytes
    }

    /// The canonical encoding of a vector, which tells apart the keys that hold reduced coefficients.
    pub fn vector_of(variant: Self, bytes: &[u8]) -> Vec<u8> {
        variant.vector(&variant.polynomials(bytes, 12), 12)
    }

    pub fn polynomials(&self, bytes: &[u8], bits: usize) -> Vec<[u16; Self::DEGREE]> {
        bytes.chunks_exact(32 * bits).map(|chunk| Self::decode(chunk, bits)).collect()
    }

    /// The key pair of the underlying encryption, from one thirty two byte seed.
    pub fn keys(&self, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut input = seed.to_vec();
        input.push(self.rank() as u8);
        let expanded = SHA3_512::digest(&input);
        let (public, secret) = expanded.split_at(32);
        let matrix = self.matrix(public, false);
        let mut nonce = 0;
        let mut keys = Vec::with_capacity(self.rank());
        for _ in 0..self.rank() {
            let mut polynomial = self.noise(secret, nonce, self.secret_noise());
            Self::transform(&mut polynomial);
            keys.push(polynomial);
            nonce += 1;
        }
        let mut errors = Vec::with_capacity(self.rank());
        for _ in 0..self.rank() {
            let mut polynomial = self.noise(secret, nonce, self.secret_noise());
            Self::transform(&mut polynomial);
            errors.push(polynomial);
            nonce += 1;
        }
        let mut values = Vec::with_capacity(self.rank());
        for (row, error) in matrix.iter().zip(&errors) {
            let mut total = *error;
            for (entry, key) in row.iter().zip(&keys) {
                total = Self::combine(&total, &Self::product(entry, key));
            }
            values.push(total);
        }
        let mut encryption = self.vector(&values, 12);
        encryption.extend_from_slice(public);
        (encryption, self.vector(&keys, 12))
    }

    /// The ciphertext of the underlying encryption, over a message and a thirty two byte seed.
    pub fn seal(&self, encryption: &[u8], message: &[u8], seed: &[u8]) -> Vec<u8> {
        let (values, public) = encryption.split_at(384 * self.rank());
        let values = self.polynomials(values, 12);
        let matrix = self.matrix(public, true);
        let mut nonce = 0;
        let mut masks = Vec::with_capacity(self.rank());
        for _ in 0..self.rank() {
            let mut polynomial = self.noise(seed, nonce, self.secret_noise());
            Self::transform(&mut polynomial);
            masks.push(polynomial);
            nonce += 1;
        }
        let mut errors = Vec::with_capacity(self.rank());
        for _ in 0..self.rank() {
            errors.push(self.noise(seed, nonce, self.error_noise()));
            nonce += 1;
        }
        let last = self.noise(seed, nonce, self.error_noise());
        let mut vector = Vec::with_capacity(self.rank());
        for (row, error) in matrix.iter().zip(&errors) {
            let mut total = [0; Self::DEGREE];
            for (entry, mask) in row.iter().zip(&masks) {
                total = Self::combine(&total, &Self::product(entry, mask));
            }
            Self::untransform(&mut total);
            vector.push(Self::combine(&total, error));
        }
        let mut constant = [0; Self::DEGREE];
        for (value, mask) in values.iter().zip(&masks) {
            constant = Self::combine(&constant, &Self::product(value, mask));
        }
        Self::untransform(&mut constant);
        let carried = Self::decode(message, 1);
        let carried: [u16; Self::DEGREE] = core::array::from_fn(|index| Self::decompress(carried[index], 1));
        constant = Self::combine(&Self::combine(&constant, &last), &carried);
        let compressed: Vec<[u16; Self::DEGREE]> = vector.iter().map(|polynomial| core::array::from_fn(|index| Self::compress(polynomial[index], self.vector_bits()))).collect();
        let mut ciphertext = self.vector(&compressed, self.vector_bits());
        let squeezed: [u16; Self::DEGREE] = core::array::from_fn(|index| Self::compress(constant[index], self.constant_bits()));
        ciphertext.extend_from_slice(&Self::encode(&squeezed, self.constant_bits()));
        ciphertext
    }

    /// The message inside a ciphertext of the underlying encryption.
    pub fn open(&self, decryption: &[u8], ciphertext: &[u8]) -> Vec<u8> {
        let (vector, constant) = ciphertext.split_at(32 * self.vector_bits() * self.rank());
        let vector: Vec<[u16; Self::DEGREE]> = self
            .polynomials(vector, self.vector_bits())
            .into_iter()
            .map(|polynomial| {
                let mut polynomial: [u16; Self::DEGREE] = core::array::from_fn(|index| Self::decompress(polynomial[index], self.vector_bits()));
                Self::transform(&mut polynomial);
                polynomial
            })
            .collect();
        let constant = Self::decode(constant, self.constant_bits());
        let constant: [u16; Self::DEGREE] = core::array::from_fn(|index| Self::decompress(constant[index], self.constant_bits()));
        let keys = self.polynomials(decryption, 12);
        let mut total = [0; Self::DEGREE];
        for (key, polynomial) in keys.iter().zip(&vector) {
            total = Self::combine(&total, &Self::product(key, polynomial));
        }
        Self::untransform(&mut total);
        let difference = Self::separate(&constant, &total);
        let message: [u16; Self::DEGREE] = core::array::from_fn(|index| Self::compress(difference[index], 1));
        Self::encode(&message, 1)
    }
}

impl fmt::Display for MLKEM {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl MLKEM {
    pub fn request(&self) -> ExchangeProviderRequest<'static> {
        ExchangeProviderRequest::new(self.as_str())
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(MLKEMPrivateKey, MLKEMPublicKey), MLKEMError> {
        match ExchangeProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((MLKEMPrivateKey { variant: *self, key: private }, MLKEMPublicKey { variant: *self, key: public })),
            None => {
                if seed.len() < self.seed_size() {
                    return Err(MLKEMError::Seed);
                }
                let (first, second) = seed.split_at(Self::SEED_SIZE);
                let (encryption, decryption) = self.keys(first);
                let mut key = decryption;
                key.extend_from_slice(&encryption);
                key.extend_from_slice(&SHA3_256::digest(&encryption));
                key.extend_from_slice(&second[..Self::SEED_SIZE]);
                Ok((MLKEMPrivateKey { variant: *self, key }, MLKEMPublicKey { variant: *self, key: encryption }))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MLKEMPrivateKey {
    variant: MLKEM,
    key: Vec<u8>,
}

impl MLKEMPrivateKey {
    pub fn decode(variant: MLKEM, data: &[u8]) -> Result<Self, MLKEMError> {
        if data.len() != variant.private_key_size() {
            return Err(MLKEMError::Encoding);
        }
        let encryption = &data[384 * variant.rank()..768 * variant.rank() + 32];
        match SHA3_256::digest(encryption).to_vec() == data[768 * variant.rank() + 32..768 * variant.rank() + 64] {
            true => Ok(Self { variant, key: data.to_vec() }),
            false => Err(MLKEMError::Key),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> MLKEM {
        self.variant
    }

    pub fn public_key(&self) -> MLKEMPublicKey {
        let request = self.variant.request();
        match ExchangeProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.public_key(&request, &self.key)) {
            Some(key) => MLKEMPublicKey { variant: self.variant, key },
            None => MLKEMPublicKey { variant: self.variant, key: self.key[384 * self.variant.rank()..768 * self.variant.rank() + 32].to_vec() },
        }
    }

    /// The shared secret behind a ciphertext, or the secret of the rejection when it does not match.
    pub fn decapsulate(&self, ciphertext: &MLKEMCiphertext) -> Result<MLKEMSharedSecret, MLKEMError> {
        if ciphertext.variant != self.variant {
            return Err(MLKEMError::Variant);
        }
        match ExchangeProviders::decapsulate(&self.variant.request(), &self.key, &ciphertext.ciphertext)? {
            Some(secret) => Ok(MLKEMSharedSecret { secret }),
            None => {
                let rank = self.variant.rank();
                let decryption = &self.key[..384 * rank];
                let encryption = &self.key[384 * rank..768 * rank + 32];
                let digest = &self.key[768 * rank + 32..768 * rank + 64];
                let rejection = &self.key[768 * rank + 64..];
                let message = self.variant.open(decryption, &ciphertext.ciphertext);
                let mut input = message.clone();
                input.extend_from_slice(digest);
                let expanded = SHA3_512::digest(&input);
                let (secret, seed) = expanded.split_at(32);
                let mut input = rejection.to_vec();
                input.extend_from_slice(&ciphertext.ciphertext);
                let mut fallback = alloc::vec![0; 32];
                SHAKE256::digest(&input, &mut fallback);
                let produced = self.variant.seal(encryption, &message, seed);
                let mut difference = 0u8;
                for (left, right) in produced.iter().zip(&ciphertext.ciphertext) {
                    difference |= left ^ right;
                }
                let mask = ((difference != 0) as u8).wrapping_neg();
                Ok(MLKEMSharedSecret { secret: secret.iter().zip(&fallback).map(|(right, wrong)| (right & !mask) | (wrong & mask)).collect() })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MLKEMPublicKey {
    variant: MLKEM,
    key: Vec<u8>,
}

impl MLKEMPublicKey {
    pub fn decode(variant: MLKEM, data: &[u8]) -> Result<Self, MLKEMError> {
        if data.len() != variant.public_key_size() {
            return Err(MLKEMError::Encoding);
        }
        let values = &data[..384 * variant.rank()];
        match MLKEM::vector_of(variant, values) == values {
            true => Ok(Self { variant, key: data.to_vec() }),
            false => Err(MLKEMError::Key),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> MLKEM {
        self.variant
    }

    pub fn encapsulate(&self, seed: &[u8]) -> Result<(MLKEMCiphertext, MLKEMSharedSecret), MLKEMError> {
        match ExchangeProviders::encapsulate(&self.variant.request().with_seed(seed), &self.key)? {
            Some((ciphertext, secret)) => Ok((MLKEMCiphertext { variant: self.variant, ciphertext }, MLKEMSharedSecret { secret })),
            None => {
                if seed.len() < MLKEM::SEED_SIZE {
                    return Err(MLKEMError::Seed);
                }
                let message = &seed[..MLKEM::SEED_SIZE];
                let mut input = message.to_vec();
                input.extend_from_slice(&SHA3_256::digest(&self.key));
                let expanded = SHA3_512::digest(&input);
                let (secret, seed) = expanded.split_at(32);
                let ciphertext = self.variant.seal(&self.key, message, seed);
                Ok((MLKEMCiphertext { variant: self.variant, ciphertext }, MLKEMSharedSecret { secret: secret.to_vec() }))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MLKEMCiphertext {
    variant: MLKEM,
    ciphertext: Vec<u8>,
}

impl MLKEMCiphertext {
    pub fn decode(variant: MLKEM, data: &[u8]) -> Result<Self, MLKEMError> {
        match data.len() == variant.ciphertext_size() {
            true => Ok(Self { variant, ciphertext: data.to_vec() }),
            false => Err(MLKEMError::Encoding),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    pub fn variant(&self) -> MLKEM {
        self.variant
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MLKEMSharedSecret {
    secret: Vec<u8>,
}

impl MLKEMSharedSecret {
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
