use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use crate::errors::ECDSAError;

use umineko_hash_sha::SHA2_256;
use umineko_helpers::provider::{SignatureProviderRequest, SignatureProviders};
use umineko_math::{Integer, Weierstrass};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ECDSA {
    SECP256R1,
    SECP384R1,
    SECP521R1,
    SECP256K1,
}

impl ECDSA {
    pub const ALL: [Self; 4] = [Self::SECP256R1, Self::SECP384R1, Self::SECP521R1, Self::SECP256K1];
    pub const DIGEST_SIZE: usize = 32;
    pub const BLOCK_SIZE: usize = 64;

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SECP256R1 => "secp256r1",
            Self::SECP384R1 => "secp384r1",
            Self::SECP521R1 => "secp521r1",
            Self::SECP256K1 => "secp256k1",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "secp256r1" => Some(Self::SECP256R1),
            "secp384r1" => Some(Self::SECP384R1),
            "secp521r1" => Some(Self::SECP521R1),
            "secp256k1" => Some(Self::SECP256K1),
            _ => None,
        }
    }

    pub fn curve(&self) -> Weierstrass {
        match self {
            Self::SECP256R1 => Weierstrass::secp256r1(),
            Self::SECP384R1 => Weierstrass::secp384r1(),
            Self::SECP521R1 => Weierstrass::secp521r1(),
            Self::SECP256K1 => Weierstrass::secp256k1(),
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Self::SECP256R1 | Self::SECP256K1 => 32,
            Self::SECP384R1 => 48,
            Self::SECP521R1 => 66,
        }
    }

    pub fn public_key_size(&self) -> usize {
        1 + self.size() * 2
    }

    pub fn private_key_size(&self) -> usize {
        self.size()
    }

    pub fn signature_size(&self) -> usize {
        self.size() * 2
    }

    pub fn seed_size(&self) -> usize {
        self.size()
    }

    /// The leftmost bits of a digest, as many as the group order holds.
    pub fn scalar(&self, digest: &[u8], order: &Integer) -> Integer {
        let value = Integer::from_bytes(digest);
        match (digest.len() * 8).checked_sub(order.bits()) {
            Some(extra) => value.shift_right(extra),
            None => value,
        }
    }

    pub fn authenticate(key: &[u8], parts: &[&[u8]]) -> [u8; Self::DIGEST_SIZE] {
        let block = |value: u8| {
            let mut block = [value; Self::BLOCK_SIZE];
            let key = match key.len() > Self::BLOCK_SIZE {
                true => SHA2_256::digest(key).to_vec(),
                false => key.to_vec(),
            };
            for (byte, source) in block.iter_mut().zip(&key) {
                *byte ^= source;
            }
            block
        };
        let mut inner = SHA2_256::builtin();
        inner.update(&block(0x36));
        for part in parts {
            inner.update(part);
        }
        let mut outer = SHA2_256::builtin();
        outer.update(&block(0x5C));
        outer.update(&inner.finalize());
        outer.finalize()
    }

    /// The nonce of one signature, drawn the deterministic way that RFC 6979 describes.
    pub fn nonce(&self, private: &[u8], digest: &[u8], order: &Integer) -> Integer {
        let size = self.private_key_size();
        let scalar = self.scalar(digest, order).modulo(order).unwrap_or_else(Integer::zero).to_bytes(size);
        let mut value = [0x01; Self::DIGEST_SIZE];
        let mut key = Self::authenticate(&[0; Self::DIGEST_SIZE], &[&value, &[0x00], private, &scalar]);
        value = Self::authenticate(&key, &[&value]);
        key = Self::authenticate(&key, &[&value, &[0x01], private, &scalar]);
        value = Self::authenticate(&key, &[&value]);
        loop {
            let mut candidate = Vec::with_capacity(size + Self::DIGEST_SIZE);
            while candidate.len() < size {
                value = Self::authenticate(&key, &[&value]);
                candidate.extend_from_slice(&value);
            }
            let nonce = self.scalar(&candidate[..size], order);
            if !nonce.is_zero() && nonce.compare(order) == Ordering::Less {
                return nonce;
            }
            key = Self::authenticate(&key, &[&value, &[0x00]]);
            value = Self::authenticate(&key, &[&value]);
        }
    }
}

impl fmt::Display for ECDSA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ECDSA {
    pub fn request(&self) -> SignatureProviderRequest<'static> {
        SignatureProviderRequest::new(self.as_str())
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(ECDSAPrivateKey, ECDSAPublicKey), ECDSAError> {
        match SignatureProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((ECDSAPrivateKey { variant: *self, key: private }, ECDSAPublicKey { variant: *self, key: public })),
            None => {
                if seed.len() < self.seed_size() {
                    return Err(ECDSAError::Seed);
                }
                let order = self.curve().order().modulus().subtract(&Integer::one());
                let scalar = Integer::from_bytes(seed).modulo(&order).unwrap_or_else(Integer::zero).add(&Integer::one());
                let private = ECDSAPrivateKey { variant: *self, key: scalar.to_bytes(self.private_key_size()) };
                let public = private.public_key();
                Ok((private, public))
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDSAPrivateKey {
    variant: ECDSA,
    key: Vec<u8>,
}

impl ECDSAPrivateKey {
    pub fn decode(variant: ECDSA, data: &[u8]) -> Result<Self, ECDSAError> {
        if data.len() != variant.private_key_size() {
            return Err(ECDSAError::Encoding);
        }
        let scalar = Integer::from_bytes(data);
        match scalar.is_zero() || scalar.compare(variant.curve().order().modulus()) != Ordering::Less {
            true => Err(ECDSAError::Key),
            false => Ok(Self { variant, key: data.to_vec() }),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> ECDSA {
        self.variant
    }

    pub fn public_key(&self) -> ECDSAPublicKey {
        let request = self.variant.request();
        match SignatureProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.public_key(&request, &self.key)) {
            Some(key) => ECDSAPublicKey { variant: self.variant, key },
            None => {
                let curve = self.variant.curve();
                let point = curve.multiply(&curve.generator(), &Integer::from_bytes(&self.key));
                ECDSAPublicKey { variant: self.variant, key: curve.encode(&point, false) }
            }
        }
    }

    /// The signature of a digest, over a nonce that the key and the digest alone decide.
    pub fn sign(&self, message: &[u8]) -> Result<ECDSASignature, ECDSAError> {
        match SignatureProviders::sign(&self.variant.request(), &self.key, message)? {
            Some(signature) => Ok(ECDSASignature { variant: self.variant, signature }),
            None => {
                let curve = self.variant.curve();
                let order = curve.order().modulus().clone();
                let secret = Integer::from_bytes(&self.key);
                let scalar = self.variant.scalar(message, &order);
                let mut nonce = self.variant.nonce(&self.key, message, &order);
                loop {
                    let point = curve.multiply(&curve.generator(), &nonce);
                    let first = curve.affine(&point).ok_or(ECDSAError::Key)?.0.modulo(&order).unwrap_or_else(Integer::zero);
                    let inverse = curve.order().inverse(&curve.order().residue(&nonce)).ok_or(ECDSAError::Key)?;
                    let product = curve.order().multiply(&curve.order().residue(&first), &curve.order().residue(&secret));
                    let sum = curve.order().add(&curve.order().residue(&scalar), &product);
                    let second = curve.order().integer(&curve.order().multiply(&inverse, &sum));
                    if !first.is_zero() && !second.is_zero() {
                        let mut signature = first.to_bytes(self.variant.size());
                        signature.extend_from_slice(&second.to_bytes(self.variant.size()));
                        return Ok(ECDSASignature { variant: self.variant, signature });
                    }
                    nonce = nonce.add(&Integer::one()).modulo(&order).unwrap_or_else(Integer::one);
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDSAPublicKey {
    variant: ECDSA,
    key: Vec<u8>,
}

impl ECDSAPublicKey {
    pub fn decode(variant: ECDSA, data: &[u8]) -> Result<Self, ECDSAError> {
        let curve = variant.curve();
        let point = curve.decode(data).map_err(|_| ECDSAError::Encoding)?;
        match point.is_identity() {
            true => Err(ECDSAError::Key),
            false => Ok(Self { variant, key: curve.encode(&point, false) }),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> ECDSA {
        self.variant
    }

    pub fn verify(&self, message: &[u8], signature: &ECDSASignature) -> Result<(), ECDSAError> {
        if signature.variant != self.variant {
            return Err(ECDSAError::Variant);
        }
        match SignatureProviders::verify(&self.variant.request(), &self.key, message, &signature.signature)? {
            Some(()) => Ok(()),
            None => {
                let curve = self.variant.curve();
                let order = curve.order().modulus().clone();
                let (first, second) = signature.parts();
                if first.is_zero() || second.is_zero() || first.compare(&order) != Ordering::Less || second.compare(&order) != Ordering::Less {
                    return Err(ECDSAError::Verification);
                }
                let point = curve.decode(&self.key).map_err(|_| ECDSAError::Key)?;
                let scalar = self.variant.scalar(message, &order);
                let inverse = curve.order().inverse(&curve.order().residue(&second)).ok_or(ECDSAError::Verification)?;
                let left = curve.order().integer(&curve.order().multiply(&inverse, &curve.order().residue(&scalar)));
                let right = curve.order().integer(&curve.order().multiply(&inverse, &curve.order().residue(&first)));
                let combined = curve.combine(&curve.generator(), &left, &point, &right);
                let Some((abscissa, _)) = curve.affine(&combined) else {
                    return Err(ECDSAError::Verification);
                };
                match abscissa.modulo(&order).unwrap_or_else(Integer::zero) == first {
                    true => Ok(()),
                    false => Err(ECDSAError::Verification),
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDSASignature {
    variant: ECDSA,
    signature: Vec<u8>,
}

impl ECDSASignature {
    /// A signature as the two scalars of the variant, each one padded to the size of the curve.
    pub fn decode(variant: ECDSA, data: &[u8]) -> Result<Self, ECDSAError> {
        match data.len() == variant.signature_size() {
            true => Ok(Self { variant, signature: data.to_vec() }),
            false => Err(ECDSAError::Length),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.signature.clone()
    }

    pub fn parts(&self) -> (Integer, Integer) {
        let (first, second) = self.signature.split_at(self.variant.size());
        (Integer::from_bytes(first), Integer::from_bytes(second))
    }

    pub fn variant(&self) -> ECDSA {
        self.variant
    }
}
