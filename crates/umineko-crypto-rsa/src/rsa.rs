use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use crate::der::DER;
use crate::errors::RSAError;

use umineko_hash_sha::{SHA1, SHA2_224, SHA2_256, SHA2_384, SHA2_512, SHAKE256};
use umineko_helpers::provider::{CipherProviderRequest, CipherProviders, SignatureProviderRequest, SignatureProviders};
use umineko_math::{Integer, Modulus, Prime};

/// The digest that a padding builds its masks and its digest information from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RSAHash {
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
}

impl RSAHash {
    pub const ALL: [Self; 5] = [Self::SHA1, Self::SHA224, Self::SHA256, Self::SHA384, Self::SHA512];

    pub fn digest_size(&self) -> usize {
        match self {
            Self::SHA1 => 20,
            Self::SHA224 => 28,
            Self::SHA256 => 32,
            Self::SHA384 => 48,
            Self::SHA512 => 64,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SHA1 => "SHA-1",
            Self::SHA224 => "SHA-224",
            Self::SHA256 => "SHA-256",
            Self::SHA384 => "SHA-384",
            Self::SHA512 => "SHA-512",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|hash| hash.as_str() == name)
    }

    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::SHA1 => SHA1::digest(data).to_vec(),
            Self::SHA224 => SHA2_224::digest(data).to_vec(),
            Self::SHA256 => SHA2_256::digest(data).to_vec(),
            Self::SHA384 => SHA2_384::digest(data).to_vec(),
            Self::SHA512 => SHA2_512::digest(data).to_vec(),
        }
    }

    /// The header that PKCS #1 puts before a digest inside a signature.
    pub fn prefix(&self) -> &'static [u8] {
        match self {
            Self::SHA1 => &[0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14],
            Self::SHA224 => &[0x30, 0x2D, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1C],
            Self::SHA256 => &[0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20],
            Self::SHA384 => &[0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30],
            Self::SHA512 => &[0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40],
        }
    }

    /// The mask generating function of PKCS #1, which is the digest over a counter.
    pub fn mask(&self, seed: &[u8], length: usize) -> Vec<u8> {
        let mut mask = Vec::with_capacity(length + self.digest_size());
        let mut counter = 0u32;
        while mask.len() < length {
            let mut input = seed.to_vec();
            input.extend_from_slice(&counter.to_be_bytes());
            mask.extend_from_slice(&self.digest(&input));
            counter += 1;
        }
        mask.truncate(length);
        mask
    }
}

impl fmt::Display for RSAHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RSAPadding {
    PKCS1V15(RSAHash),
    OAEP(RSAHash),
    PSS(RSAHash),
}

impl RSAPadding {
    pub fn encryption(&self) -> bool {
        matches!(self, Self::PKCS1V15(_) | Self::OAEP(_))
    }

    pub fn signature(&self) -> bool {
        matches!(self, Self::PKCS1V15(_) | Self::PSS(_))
    }

    pub fn hash(&self) -> RSAHash {
        match self {
            Self::PKCS1V15(hash) | Self::OAEP(hash) | Self::PSS(hash) => *hash,
        }
    }

    /// The longest message the padding leaves room for in one block.
    pub fn maximum_length(&self, modulus_size: usize) -> Option<usize> {
        let digest_size = self.hash().digest_size();
        match self {
            Self::PKCS1V15(_) => modulus_size.checked_sub(11),
            Self::OAEP(_) => modulus_size.checked_sub(2 * digest_size + 2),
            Self::PSS(_) => None,
        }
    }

    pub fn cipher_name(&self) -> Option<&'static str> {
        match self {
            Self::PKCS1V15(_) => Some("RSA-PKCS1v15"),
            Self::OAEP(RSAHash::SHA1) => Some("RSA-OAEP-SHA-1"),
            Self::OAEP(RSAHash::SHA224) => Some("RSA-OAEP-SHA-224"),
            Self::OAEP(RSAHash::SHA256) => Some("RSA-OAEP-SHA-256"),
            Self::OAEP(RSAHash::SHA384) => Some("RSA-OAEP-SHA-384"),
            Self::OAEP(RSAHash::SHA512) => Some("RSA-OAEP-SHA-512"),
            Self::PSS(_) => None,
        }
    }

    pub fn signature_name(&self) -> Option<&'static str> {
        match self {
            Self::PKCS1V15(RSAHash::SHA1) => Some("RSA-PKCS1v15-SHA-1"),
            Self::PKCS1V15(RSAHash::SHA224) => Some("RSA-PKCS1v15-SHA-224"),
            Self::PKCS1V15(RSAHash::SHA256) => Some("RSA-PKCS1v15-SHA-256"),
            Self::PKCS1V15(RSAHash::SHA384) => Some("RSA-PKCS1v15-SHA-384"),
            Self::PKCS1V15(RSAHash::SHA512) => Some("RSA-PKCS1v15-SHA-512"),
            Self::PSS(RSAHash::SHA1) => Some("RSA-PSS-SHA-1"),
            Self::PSS(RSAHash::SHA224) => Some("RSA-PSS-SHA-224"),
            Self::PSS(RSAHash::SHA256) => Some("RSA-PSS-SHA-256"),
            Self::PSS(RSAHash::SHA384) => Some("RSA-PSS-SHA-384"),
            Self::PSS(RSAHash::SHA512) => Some("RSA-PSS-SHA-512"),
            Self::OAEP(_) => None,
        }
    }

    /// One encoded block, holding the message and whatever the padding puts around it.
    pub fn pack(&self, size: usize, message: &[u8], label: &[u8], seed: &[u8]) -> Result<Vec<u8>, RSAError> {
        let hash = self.hash();
        let room = self.maximum_length(size).ok_or(RSAError::Padding)?;
        if message.len() > room {
            return Err(RSAError::Length);
        }
        match self {
            Self::PKCS1V15(_) => {
                let filling = size - message.len() - 3;
                let mut block = alloc::vec![0x00, 0x02];
                let mut mask = hash.mask(seed, filling * 2);
                mask.retain(|byte| *byte != 0);
                if mask.len() < filling {
                    return Err(RSAError::Seed);
                }
                block.extend_from_slice(&mask[..filling]);
                block.push(0);
                block.extend_from_slice(message);
                Ok(block)
            }
            Self::OAEP(_) => {
                let length = hash.digest_size();
                if seed.len() < length {
                    return Err(RSAError::Seed);
                }
                let mut database = hash.digest(label);
                database.resize(size - message.len() - length - 2, 0);
                database.push(1);
                database.extend_from_slice(message);
                let mask = hash.mask(&seed[..length], database.len());
                for (byte, source) in database.iter_mut().zip(&mask) {
                    *byte ^= source;
                }
                let mut covered = seed[..length].to_vec();
                for (byte, source) in covered.iter_mut().zip(hash.mask(&database, length)) {
                    *byte ^= source;
                }
                let mut block = alloc::vec![0];
                block.extend_from_slice(&covered);
                block.extend_from_slice(&database);
                Ok(block)
            }
            Self::PSS(_) => Err(RSAError::Padding),
        }
    }

    /// The message inside an encoded block, or an error when the padding does not hold.
    pub fn unpack(&self, size: usize, block: &[u8], label: &[u8]) -> Result<Vec<u8>, RSAError> {
        let hash = self.hash();
        if block.len() != size || size < 11 {
            return Err(RSAError::Padding);
        }
        match self {
            Self::PKCS1V15(_) => {
                let separator = block[2..].iter().position(|byte| *byte == 0).map(|position| position + 2);
                let mut wrong = (block[0] != 0) as u8 | (block[1] != 2) as u8;
                match separator {
                    Some(position) if position >= 10 => {
                        wrong |= block[2..position].contains(&0) as u8;
                        match wrong {
                            0 => Ok(block[position + 1..].to_vec()),
                            _ => Err(RSAError::Padding),
                        }
                    }
                    _ => Err(RSAError::Padding),
                }
            }
            Self::OAEP(_) => {
                let length = hash.digest_size();
                if size < 2 * length + 2 {
                    return Err(RSAError::Padding);
                }
                let (covered, database) = block[1..].split_at(length);
                let mut seed = covered.to_vec();
                for (byte, source) in seed.iter_mut().zip(hash.mask(database, length)) {
                    *byte ^= source;
                }
                let mut database = database.to_vec();
                let mask = hash.mask(&seed, database.len());
                for (byte, source) in database.iter_mut().zip(&mask) {
                    *byte ^= source;
                }
                let expected = hash.digest(label);
                let mut wrong = (block[0] != 0) as u8;
                for (left, right) in database[..length].iter().zip(&expected) {
                    wrong |= left ^ right;
                }
                let separator = database[length..].iter().position(|byte| *byte != 0);
                match separator {
                    Some(position) if database[length + position] == 1 && wrong == 0 => Ok(database[length + position + 1..].to_vec()),
                    _ => Err(RSAError::Padding),
                }
            }
            Self::PSS(_) => Err(RSAError::Padding),
        }
    }

    /// One encoded block that stands for a digest, ready to be raised to the private exponent.
    pub fn mark(&self, bits: usize, digest: &[u8], salt: &[u8]) -> Result<Vec<u8>, RSAError> {
        let hash = self.hash();
        if digest.len() != hash.digest_size() {
            return Err(RSAError::Length);
        }
        match self {
            Self::PKCS1V15(_) => {
                let size = bits.div_ceil(8);
                let mut information = hash.prefix().to_vec();
                information.extend_from_slice(digest);
                if size < information.len() + 11 {
                    return Err(RSAError::Size);
                }
                let mut block = alloc::vec![0x00, 0x01];
                block.resize(size - information.len() - 1, 0xFF);
                block.push(0);
                block.extend_from_slice(&information);
                Ok(block)
            }
            Self::PSS(_) => {
                let length = hash.digest_size();
                let size = (bits - 1).div_ceil(8);
                if size < length + salt.len() + 2 {
                    return Err(RSAError::Size);
                }
                let mut input = alloc::vec![0; 8];
                input.extend_from_slice(digest);
                input.extend_from_slice(salt);
                let seed = hash.digest(&input);
                let mut database = alloc::vec![0; size - salt.len() - length - 2];
                database.push(1);
                database.extend_from_slice(salt);
                let mask = hash.mask(&seed, database.len());
                for (byte, source) in database.iter_mut().zip(&mask) {
                    *byte ^= source;
                }
                database[0] &= 0xFF >> (size * 8 - (bits - 1));
                let mut block = database;
                block.extend_from_slice(&seed);
                block.push(0xBC);
                Ok(block)
            }
            Self::OAEP(_) => Err(RSAError::Padding),
        }
    }

    /// Whether an encoded block stands for a digest under this padding.
    pub fn check(&self, bits: usize, digest: &[u8], block: &[u8]) -> Result<(), RSAError> {
        let hash = self.hash();
        match self {
            Self::PKCS1V15(_) => match self.mark(bits, digest, &[])? == block {
                true => Ok(()),
                false => Err(RSAError::Verification),
            },
            Self::PSS(_) => {
                let length = hash.digest_size();
                let size = (bits - 1).div_ceil(8);
                if block.len() != size || size < length + 2 || block[size - 1] != 0xBC {
                    return Err(RSAError::Verification);
                }
                let (database, seed) = block[..size - 1].split_at(size - length - 1);
                if database[0] & !(0xFF >> (size * 8 - (bits - 1))) != 0 {
                    return Err(RSAError::Verification);
                }
                let mut database = database.to_vec();
                let mask = hash.mask(seed, database.len());
                for (byte, source) in database.iter_mut().zip(&mask) {
                    *byte ^= source;
                }
                database[0] &= 0xFF >> (size * 8 - (bits - 1));
                let separator = database.iter().position(|byte| *byte != 0).ok_or(RSAError::Verification)?;
                if database[separator] != 1 {
                    return Err(RSAError::Verification);
                }
                let salt = &database[separator + 1..];
                let mut input = alloc::vec![0; 8];
                input.extend_from_slice(digest);
                input.extend_from_slice(salt);
                match hash.digest(&input) == seed {
                    true => Ok(()),
                    false => Err(RSAError::Verification),
                }
            }
            Self::OAEP(_) => Err(RSAError::Padding),
        }
    }
}

impl fmt::Display for RSAPadding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PKCS1V15(hash) => write!(f, "RSA-PKCS1v15-{hash}"),
            Self::OAEP(hash) => write!(f, "RSA-OAEP-{hash}"),
            Self::PSS(hash) => write!(f, "RSA-PSS-{hash}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RSA {
    pub bits: usize,
    pub exponent: u32,
}

impl Default for RSA {
    fn default() -> Self {
        Self { bits: 3072, exponent: 65537 }
    }
}

impl RSA {
    pub const MINIMUM_BITS: usize = 2048;
    pub const NAME: &'static str = "RSA";
    pub const ROUNDS: usize = 8;

    /// A stream of bytes that only the seed decides, which the search for primes draws from.
    pub fn random(seed: &[u8], counter: &mut u64, output: &mut [u8]) {
        let mut input = seed.to_vec();
        input.extend_from_slice(&counter.to_be_bytes());
        *counter += 1;
        SHAKE256::digest(&input, output);
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(RSAPrivateKey, RSAPublicKey), RSAError> {
        match SignatureProviders::generate(&SignatureProviderRequest::new(Self::NAME).with_seed(seed))? {
            Some((private, public)) => Ok((RSAPrivateKey::decode(&private)?, RSAPublicKey::decode(&public)?)),
            None => {
                if self.bits < Self::MINIMUM_BITS || self.bits % 2 != 0 {
                    return Err(RSAError::Size);
                }
                if self.exponent < 3 || self.exponent % 2 == 0 {
                    return Err(RSAError::Key);
                }
                if seed.is_empty() {
                    return Err(RSAError::Seed);
                }
                let exponent = Integer::from_u64(self.exponent as u64);
                let mut counter = 0;
                let mut draw = |bytes: &mut [u8]| Self::random(seed, &mut counter, bytes);
                let mut primes = Vec::with_capacity(2);
                while primes.len() < 2 {
                    let candidate = Prime::generate(self.bits / 2, Self::ROUNDS, &mut draw);
                    let reduced = candidate.subtract(&Integer::one());
                    if reduced.gcd(&exponent).value() != Some(1) {
                        continue;
                    }
                    if primes.first().is_some_and(|first: &Integer| first.subtract(&candidate).absolute().bits() + 100 < self.bits / 2) {
                        continue;
                    }
                    primes.push(candidate);
                }
                let (first, second) = (primes[0].clone(), primes[1].clone());
                let modulus = first.multiply(&second);
                if modulus.bits() != self.bits {
                    return self.generate(&SHA2_256::digest(seed));
                }
                let (left, right) = (first.subtract(&Integer::one()), second.subtract(&Integer::one()));
                let total = left.multiply(&right).divide(&left.gcd(&right)).ok_or(RSAError::Key)?.0;
                let (divisor, coefficient, _) = exponent.extended_gcd(&total);
                if divisor.value() != Some(1) {
                    return Err(RSAError::Key);
                }
                let private = coefficient.modulo(&total).ok_or(RSAError::Key)?;
                let size = self.bits.div_ceil(8);
                let key = RSAPrivateKey {
                    modulus: modulus.to_bytes(size),
                    public_exponent: exponent.bytes(),
                    private_exponent: private.to_bytes(size),
                    primes: alloc::vec![first.bytes(), second.bytes()],
                };
                let public = key.public_key();
                Ok((key, public))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RSAPrivateKey {
    modulus: Vec<u8>,
    public_exponent: Vec<u8>,
    private_exponent: Vec<u8>,
    primes: Vec<Vec<u8>>,
}

impl RSAPrivateKey {
    /// A private key in the encoding that PKCS #1 gives it.
    pub fn decode(data: &[u8]) -> Result<Self, RSAError> {
        let (content, _) = DER::open(data, DER::SEQUENCE)?;
        let (version, rest) = DER::value(content)?;
        if !version.is_empty() && version != [0] {
            return Err(RSAError::Encoding);
        }
        let (modulus, rest) = DER::value(rest)?;
        let (public_exponent, rest) = DER::value(rest)?;
        let (private_exponent, rest) = DER::value(rest)?;
        let (first, rest) = DER::value(rest)?;
        let (second, _) = DER::value(rest)?;
        let key = Self { modulus, public_exponent, private_exponent, primes: alloc::vec![first, second] };
        match key.valid() {
            true => Ok(key),
            false => Err(RSAError::Key),
        }
    }

    pub fn valid(&self) -> bool {
        let modulus = Integer::from_bytes(&self.modulus);
        let product = self.primes.iter().fold(Integer::one(), |total, prime| total.multiply(&Integer::from_bytes(prime)));
        !modulus.is_zero() && modulus.is_odd() && self.primes.len() == 2 && product == modulus
    }

    pub fn encode(&self) -> Vec<u8> {
        let (first, second) = (Integer::from_bytes(&self.primes[0]), Integer::from_bytes(&self.primes[1]));
        let private = Integer::from_bytes(&self.private_exponent);
        let left = first.subtract(&Integer::one());
        let right = second.subtract(&Integer::one());
        let coefficient = Modulus::new(&first).and_then(|context| context.inverse(&context.residue(&second)).map(|value| context.integer(&value))).unwrap_or_else(Integer::zero);
        DER::sequence(&[
            DER::integer(&[0]),
            DER::integer(&self.modulus),
            DER::integer(&self.public_exponent),
            DER::integer(&self.private_exponent),
            DER::integer(&self.primes[0]),
            DER::integer(&self.primes[1]),
            DER::integer(&private.remainder(&left).unwrap_or_else(Integer::zero).bytes()),
            DER::integer(&private.remainder(&right).unwrap_or_else(Integer::zero).bytes()),
            DER::integer(&coefficient.bytes()),
        ])
    }

    pub fn public_key(&self) -> RSAPublicKey {
        RSAPublicKey { modulus: self.modulus.clone(), exponent: self.public_exponent.clone() }
    }

    pub fn bits(&self) -> usize {
        Integer::from_bytes(&self.modulus).bits()
    }

    pub fn size(&self) -> usize {
        self.bits().div_ceil(8)
    }

    /// One block raised to the private exponent, over the two primes when they are known.
    pub fn power(&self, value: &Integer) -> Result<Integer, RSAError> {
        let modulus = Integer::from_bytes(&self.modulus);
        if value.compare(&modulus) != Ordering::Less {
            return Err(RSAError::Length);
        }
        let private = Integer::from_bytes(&self.private_exponent);
        let (first, second) = (Integer::from_bytes(&self.primes[0]), Integer::from_bytes(&self.primes[1]));
        let (Some(left), Some(right)) = (Modulus::new(&first), Modulus::new(&second)) else {
            return Modulus::new(&modulus).map(|context| context.exponentiate(value, &private)).ok_or(RSAError::Key);
        };
        let one = Integer::one();
        let inner = left.exponentiate(value, &private.remainder(&first.subtract(&one)).unwrap_or_else(Integer::zero));
        let outer = right.exponentiate(value, &private.remainder(&second.subtract(&one)).unwrap_or_else(Integer::zero));
        let coefficient = left.inverse(&left.residue(&second)).ok_or(RSAError::Key)?;
        let difference = left.subtract(&left.residue(&inner), &left.residue(&outer));
        let factor = left.integer(&left.multiply(&coefficient, &difference));
        Ok(outer.add(&factor.multiply(&second)))
    }

    pub fn decrypt(&self, padding: RSAPadding, ciphertext: &[u8], label: &[u8]) -> Result<Vec<u8>, RSAError> {
        let name = padding.cipher_name().ok_or(RSAError::Padding)?;
        let key = self.encode();
        match CipherProviders::decrypt(&CipherProviderRequest::new(name, &key).with_associated(label), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => {
                if ciphertext.len() != self.size() {
                    return Err(RSAError::Length);
                }
                let block = self.power(&Integer::from_bytes(ciphertext))?.to_bytes(self.size());
                padding.unpack(self.size(), &block, label)
            }
        }
    }

    pub fn sign(&self, padding: RSAPadding, digest: &[u8], salt: &[u8]) -> Result<RSASignature, RSAError> {
        let name = padding.signature_name().ok_or(RSAError::Padding)?;
        match SignatureProviders::sign(&SignatureProviderRequest::new(name).with_context(salt), &self.encode(), digest)? {
            Some(signature) => Ok(RSASignature { signature }),
            None => {
                let block = padding.mark(self.bits(), digest, salt)?;
                let signature = self.power(&Integer::from_bytes(&block))?.to_bytes(self.size());
                Ok(RSASignature { signature })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RSAPublicKey {
    modulus: Vec<u8>,
    exponent: Vec<u8>,
}

impl RSAPublicKey {
    pub fn decode(data: &[u8]) -> Result<Self, RSAError> {
        let (content, _) = DER::open(data, DER::SEQUENCE)?;
        let (modulus, rest) = DER::value(content)?;
        let (exponent, _) = DER::value(rest)?;
        let key = Self { modulus, exponent };
        match Integer::from_bytes(&key.modulus).is_odd() && Integer::from_bytes(&key.exponent).is_odd() {
            true => Ok(key),
            false => Err(RSAError::Key),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        DER::sequence(&[DER::integer(&self.modulus), DER::integer(&self.exponent)])
    }

    pub fn bits(&self) -> usize {
        Integer::from_bytes(&self.modulus).bits()
    }

    pub fn size(&self) -> usize {
        self.bits().div_ceil(8)
    }

    pub fn power(&self, value: &Integer) -> Result<Integer, RSAError> {
        let modulus = Integer::from_bytes(&self.modulus);
        if value.compare(&modulus) != Ordering::Less {
            return Err(RSAError::Length);
        }
        let context = Modulus::new(&modulus).ok_or(RSAError::Key)?;
        Ok(context.exponentiate(value, &Integer::from_bytes(&self.exponent)))
    }

    pub fn encrypt(&self, padding: RSAPadding, plaintext: &[u8], label: &[u8], seed: &[u8]) -> Result<Vec<u8>, RSAError> {
        let name = padding.cipher_name().ok_or(RSAError::Padding)?;
        let key = self.encode();
        match CipherProviders::encrypt(&CipherProviderRequest::new(name, &key).with_nonce(seed).with_associated(label), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => {
                let block = padding.pack(self.size(), plaintext, label, seed)?;
                Ok(self.power(&Integer::from_bytes(&block))?.to_bytes(self.size()))
            }
        }
    }

    pub fn verify(&self, padding: RSAPadding, digest: &[u8], signature: &RSASignature) -> Result<(), RSAError> {
        let name = padding.signature_name().ok_or(RSAError::Padding)?;
        match SignatureProviders::verify(&SignatureProviderRequest::new(name), &self.encode(), digest, &signature.signature)? {
            Some(()) => Ok(()),
            None => {
                if signature.signature.len() != self.size() {
                    return Err(RSAError::Length);
                }
                let value = self.power(&Integer::from_bytes(&signature.signature))?;
                let length = match padding {
                    RSAPadding::PSS(_) => (self.bits() - 1).div_ceil(8),
                    _ => self.size(),
                };
                padding.check(self.bits(), digest, &value.to_bytes(length))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RSASignature {
    signature: Vec<u8>,
}

impl RSASignature {
    pub fn decode(data: &[u8]) -> Result<Self, RSAError> {
        Ok(Self { signature: data.to_vec() })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.signature.clone()
    }
}
