use alloc::vec::Vec;
use core::fmt;
use crate::errors::MLDSAError;

use umineko_hash_sha::{SHAKE128, SHAKE256};
use umineko_helpers::provider::{SignatureProviderRequest, SignatureProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MLDSA {
    V44,
    V65,
    V87,
}

impl MLDSA {
    pub const ALL: [Self; 3] = [Self::V44, Self::V65, Self::V87];
    pub const MODULUS: i32 = 8_380_417;
    pub const DEGREE: usize = 256;
    /// The bits of every coefficient that the public key drops.
    pub const DROPPED: usize = 13;
    /// The inverse of two hundred and fifty six, which closes the inverse transform.
    pub const SCALE: i64 = 8_347_681;
    pub const SEED_SIZE: usize = 32;
    pub const MAXIMUM_CONTEXT_SIZE: usize = 255;
    pub const ZETAS: [i32; 256] = [
        1, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987,
        7778734, 3542485, 2682288, 2129892, 3764867, 7375178, 557458, 7159240,
        5010068, 4317364, 2663378, 6705802, 4855975, 7946292, 676590, 7044481,
        5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733,
        3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875,
        394148, 928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050,
        3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364,
        5483103, 3192354, 556856, 3870317, 2917338, 1853806, 3345963, 1858416,
        3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357,
        2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088,
        1528066, 482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034,
        4213992, 4892034, 1987814, 5183169, 1736313, 235407, 5130263, 3258457,
        5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354,
        7062739, 2461387, 3035980, 621164, 3901472, 7153756, 2925816, 3374250,
        1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
        348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507,
        1753, 6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600,
        1182243, 87208, 636927, 4415111, 4423672, 6084020, 5095502, 4663471,
        8352605, 822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952,
        6695264, 4969849, 2678278, 4611469, 4829411, 635956, 8129971, 5925040,
        4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961,
        3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000,
        2998219, 141835, 8291116, 2513018, 7025525, 613238, 7070156, 6161950,
        7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452,
        6757063, 2105286, 6006015, 6346610, 586241, 7200804, 527981, 5637006,
        6903432, 1994046, 2491325, 6987258, 507927, 7192532, 7655613, 6545891,
        5346675, 8041997, 2647994, 3009748, 5767564, 4148469, 749577, 4357667,
        3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144,
        3994671, 8368538, 7009900, 3020393, 3363542, 214880, 545376, 7609976,
        3105558, 7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265,
        6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710,
        8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V44 => "ML-DSA-44",
            Self::V65 => "ML-DSA-65",
            Self::V87 => "ML-DSA-87",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ML-DSA-44" => Some(Self::V44),
            "ML-DSA-65" => Some(Self::V65),
            "ML-DSA-87" => Some(Self::V87),
            _ => None,
        }
    }

    pub fn rows(&self) -> usize {
        match self {
            Self::V44 => 4,
            Self::V65 => 6,
            Self::V87 => 8,
        }
    }

    pub fn columns(&self) -> usize {
        match self {
            Self::V44 => 4,
            Self::V65 => 5,
            Self::V87 => 7,
        }
    }

    pub fn noise(&self) -> i32 {
        match self {
            Self::V44 | Self::V87 => 2,
            Self::V65 => 4,
        }
    }

    /// The number of non zero coefficients of the challenge.
    pub fn weight(&self) -> usize {
        match self {
            Self::V44 => 39,
            Self::V65 => 49,
            Self::V87 => 60,
        }
    }

    pub fn boundary(&self) -> i32 {
        self.weight() as i32 * self.noise()
    }

    pub fn mask(&self) -> i32 {
        match self {
            Self::V44 => 1 << 17,
            Self::V65 | Self::V87 => 1 << 19,
        }
    }

    pub fn window(&self) -> i32 {
        match self {
            Self::V44 => (Self::MODULUS - 1) / 88,
            Self::V65 | Self::V87 => (Self::MODULUS - 1) / 32,
        }
    }

    pub fn hints(&self) -> usize {
        match self {
            Self::V44 => 80,
            Self::V65 => 55,
            Self::V87 => 75,
        }
    }

    /// The length of the commitment that opens every signature.
    pub fn commitment(&self) -> usize {
        match self {
            Self::V44 => 32,
            Self::V65 => 48,
            Self::V87 => 64,
        }
    }

    pub fn noise_bits(&self) -> usize {
        match self.noise() {
            2 => 3,
            _ => 4,
        }
    }

    pub fn mask_bits(&self) -> usize {
        match self.mask() {
            131_072 => 18,
            _ => 20,
        }
    }

    pub fn window_bits(&self) -> usize {
        match self.window() {
            95_232 => 6,
            _ => 4,
        }
    }

    pub fn public_key_size(&self) -> usize {
        32 + 320 * self.rows()
    }

    pub fn private_key_size(&self) -> usize {
        128 + 32 * ((self.rows() + self.columns()) * self.noise_bits() + Self::DROPPED * self.rows())
    }

    pub fn signature_size(&self) -> usize {
        self.commitment() + self.columns() * 32 * self.mask_bits() + self.hints() + self.rows()
    }

    pub fn seed_size(&self) -> usize {
        Self::SEED_SIZE
    }

    pub fn reduce(value: i64) -> i32 {
        let reduced = (value % Self::MODULUS as i64) as i32;
        match reduced < 0 {
            true => reduced + Self::MODULUS,
            false => reduced,
        }
    }

    /// The representative of `value` that lies closest to zero.
    pub fn centered(value: i32, span: i32) -> i32 {
        let reduced = value.rem_euclid(span);
        match reduced > span / 2 {
            true => reduced - span,
            false => reduced,
        }
    }

    pub fn infinity(polynomial: &[i32; Self::DEGREE]) -> i32 {
        polynomial.iter().map(|value| Self::centered(*value, Self::MODULUS).abs()).max().unwrap_or(0)
    }

    pub fn transform(polynomial: &mut [i32; Self::DEGREE]) {
        let mut index = 0;
        let mut length = 128;
        while length >= 1 {
            for start in (0..Self::DEGREE).step_by(length * 2) {
                index += 1;
                let zeta = Self::ZETAS[index] as i64;
                for position in start..start + length {
                    let step = Self::reduce(zeta * polynomial[position + length] as i64);
                    polynomial[position + length] = Self::reduce(polynomial[position] as i64 - step as i64);
                    polynomial[position] = Self::reduce(polynomial[position] as i64 + step as i64);
                }
            }
            length /= 2;
        }
    }

    pub fn untransform(polynomial: &mut [i32; Self::DEGREE]) {
        let mut index = 256;
        let mut length = 1;
        while length < Self::DEGREE {
            for start in (0..Self::DEGREE).step_by(length * 2) {
                index -= 1;
                let zeta = -(Self::ZETAS[index] as i64);
                for position in start..start + length {
                    let step = polynomial[position];
                    polynomial[position] = Self::reduce(step as i64 + polynomial[position + length] as i64);
                    polynomial[position + length] = Self::reduce(zeta * (step as i64 - polynomial[position + length] as i64));
                }
            }
            length *= 2;
        }
        for value in polynomial.iter_mut() {
            *value = Self::reduce(Self::SCALE * *value as i64);
        }
    }

    pub fn product(left: &[i32; Self::DEGREE], right: &[i32; Self::DEGREE]) -> [i32; Self::DEGREE] {
        core::array::from_fn(|index| Self::reduce(left[index] as i64 * right[index] as i64))
    }

    pub fn combine(left: &[i32; Self::DEGREE], right: &[i32; Self::DEGREE]) -> [i32; Self::DEGREE] {
        core::array::from_fn(|index| Self::reduce(left[index] as i64 + right[index] as i64))
    }

    pub fn separate(left: &[i32; Self::DEGREE], right: &[i32; Self::DEGREE]) -> [i32; Self::DEGREE] {
        core::array::from_fn(|index| Self::reduce(left[index] as i64 - right[index] as i64))
    }

    /// The high and the low halves of one coefficient, split at two to the dropped bits.
    pub fn split(value: i32) -> (i32, i32) {
        let low = Self::centered(value, 1 << Self::DROPPED);
        ((value - low) >> Self::DROPPED, low)
    }

    /// The high and the low parts of one coefficient, split at twice the window.
    pub fn decompose(&self, value: i32) -> (i32, i32) {
        let value = value.rem_euclid(Self::MODULUS);
        let low = Self::centered(value, 2 * self.window());
        match value - low == Self::MODULUS - 1 {
            true => (0, low - 1),
            false => ((value - low) / (2 * self.window()), low),
        }
    }

    pub fn hint(&self, difference: i32, value: i32) -> bool {
        self.decompose(value).0 != self.decompose(Self::reduce(value as i64 + difference as i64)).0
    }

    pub fn recover(&self, hint: bool, value: i32) -> i32 {
        let steps = (Self::MODULUS - 1) / (2 * self.window());
        let (high, low) = self.decompose(value);
        match (hint, low > 0) {
            (false, _) => high,
            (true, true) => (high + 1).rem_euclid(steps),
            (true, false) => (high - 1).rem_euclid(steps),
        }
    }

    /// The coefficients of one polynomial as `bits` bits each, taken as they are.
    pub fn pack(polynomial: &[i32; Self::DEGREE], bits: usize) -> Vec<u8> {
        let mut bytes = alloc::vec![0; Self::DEGREE * bits / 8];
        for (index, value) in polynomial.iter().enumerate() {
            for bit in 0..bits {
                let position = index * bits + bit;
                bytes[position / 8] |= (((value >> bit) & 1) as u8) << (position % 8);
            }
        }
        bytes
    }

    pub fn unpack(bytes: &[u8], bits: usize) -> [i32; Self::DEGREE] {
        let mut polynomial = [0; Self::DEGREE];
        for (index, value) in polynomial.iter_mut().enumerate() {
            for bit in 0..bits {
                let position = index * bits + bit;
                *value |= (((bytes[position / 8] >> (position % 8)) & 1) as i32) << bit;
            }
        }
        polynomial
    }

    /// The coefficients of one polynomial as offsets below `bound`, which keeps them positive.
    pub fn pack_signed(polynomial: &[i32; Self::DEGREE], bound: i32, bits: usize) -> Vec<u8> {
        let shifted: [i32; Self::DEGREE] = core::array::from_fn(|index| bound - Self::centered(polynomial[index], Self::MODULUS));
        Self::pack(&shifted, bits)
    }

    pub fn unpack_signed(bytes: &[u8], bound: i32, bits: usize) -> [i32; Self::DEGREE] {
        let packed = Self::unpack(bytes, bits);
        core::array::from_fn(|index| Self::reduce(bound as i64 - packed[index] as i64))
    }

    pub fn digest(parts: &[&[u8]], output: &mut [u8]) {
        let mut hash = SHAKE256::builtin();
        for part in parts {
            hash.update(part);
        }
        hash.finalize(output);
    }

    /// One polynomial of the public matrix, drawn from the seed and the two indices.
    pub fn sample(seed: &[u8], first: u8, second: u8) -> [i32; Self::DEGREE] {
        let mut input = seed.to_vec();
        input.push(first);
        input.push(second);
        let mut polynomial = [0; Self::DEGREE];
        let mut length = 1024;
        loop {
            let mut stream = alloc::vec![0; length];
            SHAKE128::digest(&input, &mut stream);
            let mut filled = 0;
            for chunk in stream.chunks_exact(3) {
                let candidate = chunk[0] as i32 | ((chunk[1] as i32) << 8) | (((chunk[2] as i32) & 0x7F) << 16);
                if candidate < Self::MODULUS && filled < Self::DEGREE {
                    polynomial[filled] = candidate;
                    filled += 1;
                }
            }
            if filled == Self::DEGREE {
                return polynomial;
            }
            length *= 2;
        }
    }

    /// One polynomial of small coefficients, drawn four bits at a time.
    pub fn bounded(&self, seed: &[u8], index: u16) -> [i32; Self::DEGREE] {
        let mut input = seed.to_vec();
        input.extend_from_slice(&index.to_le_bytes());
        let mut polynomial = [0; Self::DEGREE];
        let mut length = 512;
        loop {
            let mut stream = alloc::vec![0; length];
            SHAKE256::digest(&input, &mut stream);
            let mut filled = 0;
            for byte in &stream {
                for half in [byte & 0x0F, byte >> 4] {
                    let value = match self.noise() {
                        2 if half < 15 => Some(2 - (half as i32 % 5)),
                        4 if half < 9 => Some(4 - half as i32),
                        _ => None,
                    };
                    if let Some(value) = value {
                        if filled < Self::DEGREE {
                            polynomial[filled] = Self::reduce(value as i64);
                            filled += 1;
                        }
                    }
                }
            }
            if filled == Self::DEGREE {
                return polynomial;
            }
            length *= 2;
        }
    }

    /// The challenge polynomial, which holds as many signs as the weight of the variant.
    pub fn challenge(&self, seed: &[u8]) -> [i32; Self::DEGREE] {
        let mut stream = alloc::vec![0; 8 + 272];
        SHAKE256::digest(seed, &mut stream);
        let signs = u64::from_le_bytes(stream[..8].try_into().unwrap_or([0; 8]));
        let mut polynomial = [0; Self::DEGREE];
        let mut position = 8;
        for (step, index) in (Self::DEGREE - self.weight()..Self::DEGREE).enumerate() {
            let mut chosen = stream[position] as usize;
            position += 1;
            while chosen > index {
                if position == stream.len() {
                    stream.resize(stream.len() * 2, 0);
                    SHAKE256::digest(seed, &mut stream);
                }
                chosen = stream[position] as usize;
                position += 1;
            }
            polynomial[index] = polynomial[chosen];
            polynomial[chosen] = match (signs >> step) & 1 {
                0 => 1,
                _ => Self::MODULUS - 1,
            };
        }
        polynomial
    }

    /// The mask of one attempt, one polynomial for each column.
    pub fn expand(&self, seed: &[u8], counter: u16) -> Vec<[i32; Self::DEGREE]> {
        (0..self.columns())
            .map(|index| {
                let mut input = seed.to_vec();
                input.extend_from_slice(&(counter + index as u16).to_le_bytes());
                let mut stream = alloc::vec![0; 32 * self.mask_bits()];
                SHAKE256::digest(&input, &mut stream);
                Self::unpack_signed(&stream, self.mask(), self.mask_bits())
            })
            .collect()
    }

    pub fn matrix(&self, seed: &[u8]) -> Vec<Vec<[i32; Self::DEGREE]>> {
        (0..self.rows()).map(|row| (0..self.columns()).map(|column| Self::sample(seed, column as u8, row as u8)).collect()).collect()
    }

    /// The product of the public matrix and one vector, in the transformed domain.
    pub fn apply(&self, matrix: &[Vec<[i32; Self::DEGREE]>], vector: &[[i32; Self::DEGREE]]) -> Vec<[i32; Self::DEGREE]> {
        matrix
            .iter()
            .map(|row| {
                let mut total = [0; Self::DEGREE];
                for (entry, value) in row.iter().zip(vector) {
                    total = Self::combine(&total, &Self::product(entry, value));
                }
                total
            })
            .collect()
    }

    /// The message that a signature covers, which names the context it belongs to.
    pub fn bound(context: &[u8], message: &[u8]) -> Vec<u8> {
        let mut bound = alloc::vec![0, context.len() as u8];
        bound.extend_from_slice(context);
        bound.extend_from_slice(message);
        bound
    }
}

impl fmt::Display for MLDSA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl MLDSA {
    /// The key pair of one seed, as the encodings that FIPS 204 gives them.
    pub fn keys(&self, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut input = seed[..Self::SEED_SIZE].to_vec();
        input.push(self.rows() as u8);
        input.push(self.columns() as u8);
        let mut expanded = alloc::vec![0; 128];
        Self::digest(&[&input], &mut expanded);
        let (public, rest) = expanded.split_at(32);
        let (secret, signing) = rest.split_at(64);
        let matrix = self.matrix(public);
        let mut keys: Vec<[i32; Self::DEGREE]> = (0..self.columns()).map(|index| self.bounded(secret, index as u16)).collect();
        let errors: Vec<[i32; Self::DEGREE]> = (0..self.rows()).map(|index| self.bounded(secret, (self.columns() + index) as u16)).collect();
        let mut transformed = keys.clone();
        for polynomial in transformed.iter_mut() {
            Self::transform(polynomial);
        }
        let mut values = self.apply(&matrix, &transformed);
        for (value, error) in values.iter_mut().zip(&errors) {
            Self::untransform(value);
            *value = Self::combine(value, error);
        }
        let mut encoded = public.to_vec();
        let mut low = Vec::with_capacity(self.rows());
        for value in &values {
            let mut high = [0; Self::DEGREE];
            let mut rest = [0; Self::DEGREE];
            for index in 0..Self::DEGREE {
                let (top, bottom) = Self::split(value[index]);
                high[index] = top;
                rest[index] = bottom;
            }
            encoded.extend_from_slice(&Self::pack(&high, 10));
            low.push(rest);
        }
        let mut digest = alloc::vec![0; 64];
        Self::digest(&[&encoded], &mut digest);
        let mut key = public.to_vec();
        key.extend_from_slice(signing);
        key.extend_from_slice(&digest);
        keys.extend_from_slice(&errors);
        for polynomial in &keys {
            key.extend_from_slice(&Self::pack_signed(polynomial, self.noise(), self.noise_bits()));
        }
        for polynomial in &low {
            key.extend_from_slice(&Self::pack_signed(polynomial, 1 << (Self::DROPPED - 1), Self::DROPPED));
        }
        (encoded, key)
    }

    /// The hints of one signature, as the positions that FIPS 204 lists.
    pub fn pack_hints(&self, hints: &[[bool; Self::DEGREE]]) -> Vec<u8> {
        let mut packed = alloc::vec![0; self.hints() + self.rows()];
        let mut index = 0;
        for (row, hint) in hints.iter().enumerate() {
            for (position, set) in hint.iter().enumerate() {
                if *set && index < self.hints() {
                    packed[index] = position as u8;
                    index += 1;
                }
            }
            packed[self.hints() + row] = index as u8;
        }
        packed
    }

    pub fn unpack_hints(&self, packed: &[u8]) -> Option<Vec<[bool; Self::DEGREE]>> {
        let mut hints = alloc::vec![[false; Self::DEGREE]; self.rows()];
        let mut index = 0usize;
        for (row, hint) in hints.iter_mut().enumerate() {
            let bound = packed[self.hints() + row] as usize;
            if bound < index || bound > self.hints() {
                return None;
            }
            let first = index;
            while index < bound {
                if index > first && packed[index - 1] >= packed[index] {
                    return None;
                }
                hint[packed[index] as usize] = true;
                index += 1;
            }
        }
        match packed[index..self.hints()].iter().all(|byte| *byte == 0) {
            true => Some(hints),
            false => None,
        }
    }

    /// The vectors that a private key holds, in the order that its encoding lists them.
    #[allow(clippy::type_complexity)]
    pub fn parts(&self, key: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<[i32; Self::DEGREE]>, Vec<[i32; Self::DEGREE]>, Vec<[i32; Self::DEGREE]>) {
        let (public, rest) = key.split_at(32);
        let (signing, rest) = rest.split_at(32);
        let (digest, rest) = rest.split_at(64);
        let size = 32 * self.noise_bits();
        let (keys, rest) = rest.split_at(size * self.columns());
        let (errors, low) = rest.split_at(size * self.rows());
        let unpack = |bytes: &[u8]| bytes.chunks_exact(size).map(|chunk| Self::unpack_signed(chunk, self.noise(), self.noise_bits())).collect::<Vec<_>>();
        let low = low.chunks_exact(32 * Self::DROPPED).map(|chunk| Self::unpack_signed(chunk, 1 << (Self::DROPPED - 1), Self::DROPPED)).collect();
        (public.to_vec(), signing.to_vec(), digest.to_vec(), unpack(keys), unpack(errors), low)
    }

    pub fn commit(&self, values: &[[i32; Self::DEGREE]]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(values.len() * 32 * self.window_bits());
        for value in values {
            encoded.extend_from_slice(&Self::pack(value, self.window_bits()));
        }
        encoded
    }

    /// One signature of a message under a private key, over as many attempts as it takes.
    pub fn produce(&self, key: &[u8], message: &[u8]) -> Vec<u8> {
        let (public, signing, digest, keys, errors, low) = self.parts(key);
        let matrix = self.matrix(&public);
        let transform = |values: &[[i32; Self::DEGREE]]| {
            values
                .iter()
                .map(|value| {
                    let mut value = *value;
                    Self::transform(&mut value);
                    value
                })
                .collect::<Vec<_>>()
        };
        let (keys, errors, low) = (transform(&keys), transform(&errors), transform(&low));
        let mut inner = alloc::vec![0; 64];
        Self::digest(&[&digest, message], &mut inner);
        let mut seed = alloc::vec![0; 64];
        Self::digest(&[&signing, &[0; 32], &inner], &mut seed);
        let mut counter = 0u16;
        loop {
            let masks = self.expand(&seed, counter);
            counter += self.columns() as u16;
            let mut commitments = self.apply(&matrix, &transform(&masks));
            for value in commitments.iter_mut() {
                Self::untransform(value);
            }
            let highs: Vec<[i32; Self::DEGREE]> = commitments.iter().map(|value| core::array::from_fn(|index| self.decompose(value[index]).0)).collect();
            let mut commitment = alloc::vec![0; self.commitment()];
            Self::digest(&[&inner, &self.commit(&highs)], &mut commitment);
            let mut challenge = self.challenge(&commitment);
            Self::transform(&mut challenge);
            let scaled = |values: &[[i32; Self::DEGREE]]| {
                values
                    .iter()
                    .map(|value| {
                        let mut product = Self::product(&challenge, value);
                        Self::untransform(&mut product);
                        product
                    })
                    .collect::<Vec<_>>()
            };
            let (products, noises, offsets) = (scaled(&keys), scaled(&errors), scaled(&low));
            let proofs: Vec<[i32; Self::DEGREE]> = masks.iter().zip(&products).map(|(mask, product)| Self::combine(mask, product)).collect();
            let differences: Vec<[i32; Self::DEGREE]> = commitments.iter().zip(&noises).map(|(value, noise)| Self::separate(value, noise)).collect();
            let lows: Vec<[i32; Self::DEGREE]> = differences.iter().map(|value| core::array::from_fn(|index| self.decompose(value[index]).1)).collect();
            if proofs.iter().any(|proof| Self::infinity(proof) >= self.mask() - self.boundary()) {
                continue;
            }
            if lows.iter().any(|low| Self::infinity(low) >= self.window() - self.boundary()) {
                continue;
            }
            if offsets.iter().any(|offset| Self::infinity(offset) >= self.window()) {
                continue;
            }
            let hints: Vec<[bool; Self::DEGREE]> = differences
                .iter()
                .zip(&offsets)
                .map(|(value, offset)| core::array::from_fn(|index| self.hint(-Self::centered(offset[index], Self::MODULUS), Self::reduce(value[index] as i64 + offset[index] as i64))))
                .collect();
            if hints.iter().map(|hint| hint.iter().filter(|set| **set).count()).sum::<usize>() > self.hints() {
                continue;
            }
            let mut signature = commitment;
            for proof in &proofs {
                signature.extend_from_slice(&Self::pack_signed(proof, self.mask(), self.mask_bits()));
            }
            signature.extend_from_slice(&self.pack_hints(&hints));
            return signature;
        }
    }

    /// Whether one signature belongs to a message under a public key.
    pub fn confirm(&self, key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let (public, packed) = key.split_at(32);
        let values: Vec<[i32; Self::DEGREE]> = packed.chunks_exact(320).map(|chunk| Self::unpack(chunk, 10)).collect();
        let (commitment, rest) = signature.split_at(self.commitment());
        let (proofs, hints) = rest.split_at(self.columns() * 32 * self.mask_bits());
        let proofs: Vec<[i32; Self::DEGREE]> = proofs.chunks_exact(32 * self.mask_bits()).map(|chunk| Self::unpack_signed(chunk, self.mask(), self.mask_bits())).collect();
        let Some(hints) = self.unpack_hints(hints) else {
            return false;
        };
        if proofs.iter().any(|proof| Self::infinity(proof) >= self.mask() - self.boundary()) {
            return false;
        }
        let mut digest = alloc::vec![0; 64];
        Self::digest(&[key], &mut digest);
        let mut inner = alloc::vec![0; 64];
        Self::digest(&[&digest, message], &mut inner);
        let mut challenge = self.challenge(commitment);
        Self::transform(&mut challenge);
        let matrix = self.matrix(public);
        let transformed: Vec<[i32; Self::DEGREE]> = proofs
            .iter()
            .map(|proof| {
                let mut proof = *proof;
                Self::transform(&mut proof);
                proof
            })
            .collect();
        let mut commitments = self.apply(&matrix, &transformed);
        for (value, high) in commitments.iter_mut().zip(&values) {
            let mut lifted: [i32; Self::DEGREE] = core::array::from_fn(|index| Self::reduce((high[index] as i64) << Self::DROPPED));
            Self::transform(&mut lifted);
            *value = Self::separate(value, &Self::product(&challenge, &lifted));
            Self::untransform(value);
        }
        let highs: Vec<[i32; Self::DEGREE]> = commitments.iter().zip(&hints).map(|(value, hint)| core::array::from_fn(|index| self.recover(hint[index], value[index]))).collect();
        let mut produced = alloc::vec![0; self.commitment()];
        Self::digest(&[&inner, &self.commit(&highs)], &mut produced);
        produced == commitment
    }
}

impl MLDSA {
    pub fn request(&self) -> SignatureProviderRequest<'static> {
        SignatureProviderRequest::new(self.as_str())
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(MLDSAPrivateKey, MLDSAPublicKey), MLDSAError> {
        match SignatureProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((MLDSAPrivateKey { variant: *self, key: private }, MLDSAPublicKey { variant: *self, key: public })),
            None => {
                if seed.len() < self.seed_size() {
                    return Err(MLDSAError::Seed);
                }
                let (public, private) = self.keys(seed);
                Ok((MLDSAPrivateKey { variant: *self, key: private }, MLDSAPublicKey { variant: *self, key: public }))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MLDSAPrivateKey {
    variant: MLDSA,
    key: Vec<u8>,
}

impl MLDSAPrivateKey {
    pub fn decode(variant: MLDSA, data: &[u8]) -> Result<Self, MLDSAError> {
        match data.len() == variant.private_key_size() {
            true => Ok(Self { variant, key: data.to_vec() }),
            false => Err(MLDSAError::Encoding),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> MLDSA {
        self.variant
    }

    /// The public key that the private key carries, rebuilt from the seed and the parts it holds.
    pub fn public_key(&self) -> MLDSAPublicKey {
        let request = self.variant.request();
        match SignatureProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.public_key(&request, &self.key)) {
            Some(key) => MLDSAPublicKey { variant: self.variant, key },
            None => {
                let (public, _, _, keys, errors, low) = self.variant.parts(&self.key);
                let matrix = self.variant.matrix(&public);
                let transformed: Vec<[i32; MLDSA::DEGREE]> = keys
                    .iter()
                    .map(|value| {
                        let mut value = *value;
                        MLDSA::transform(&mut value);
                        value
                    })
                    .collect();
                let mut values = self.variant.apply(&matrix, &transformed);
                let mut key = public;
                for ((value, error), rest) in values.iter_mut().zip(&errors).zip(&low) {
                    MLDSA::untransform(value);
                    let total = MLDSA::combine(value, error);
                    let high: [i32; MLDSA::DEGREE] = core::array::from_fn(|index| MLDSA::reduce(total[index] as i64 - MLDSA::centered(rest[index], MLDSA::MODULUS) as i64) >> MLDSA::DROPPED);
                    key.extend_from_slice(&MLDSA::pack(&high, 10));
                }
                MLDSAPublicKey { variant: self.variant, key }
            }
        }
    }

    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<MLDSASignature, MLDSAError> {
        if context.len() > MLDSA::MAXIMUM_CONTEXT_SIZE {
            return Err(MLDSAError::Length);
        }
        match SignatureProviders::sign(&self.variant.request().with_context(context), &self.key, message)? {
            Some(signature) => Ok(MLDSASignature { variant: self.variant, signature }),
            None => Ok(MLDSASignature { variant: self.variant, signature: self.variant.produce(&self.key, &MLDSA::bound(context, message)) }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MLDSAPublicKey {
    variant: MLDSA,
    key: Vec<u8>,
}

impl MLDSAPublicKey {
    pub fn decode(variant: MLDSA, data: &[u8]) -> Result<Self, MLDSAError> {
        match data.len() == variant.public_key_size() {
            true => Ok(Self { variant, key: data.to_vec() }),
            false => Err(MLDSAError::Encoding),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> MLDSA {
        self.variant
    }

    pub fn verify(&self, message: &[u8], signature: &MLDSASignature, context: &[u8]) -> Result<(), MLDSAError> {
        if signature.variant != self.variant {
            return Err(MLDSAError::Variant);
        }
        if context.len() > MLDSA::MAXIMUM_CONTEXT_SIZE {
            return Err(MLDSAError::Length);
        }
        match SignatureProviders::verify(&self.variant.request().with_context(context), &self.key, message, &signature.signature)? {
            Some(()) => Ok(()),
            None => match self.variant.confirm(&self.key, &MLDSA::bound(context, message), &signature.signature) {
                true => Ok(()),
                false => Err(MLDSAError::Verification),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MLDSASignature {
    variant: MLDSA,
    signature: Vec<u8>,
}

impl MLDSASignature {
    pub fn decode(variant: MLDSA, data: &[u8]) -> Result<Self, MLDSAError> {
        match data.len() == variant.signature_size() {
            true => Ok(Self { variant, signature: data.to_vec() }),
            false => Err(MLDSAError::Encoding),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.signature.clone()
    }

    pub fn variant(&self) -> MLDSA {
        self.variant
    }
}
