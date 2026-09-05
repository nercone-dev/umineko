use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use crate::errors::EdDSAError;

use umineko_hash_sha::{SHA2_512, SHAKE256};
use umineko_helpers::provider::{SignatureProviderRequest, SignatureProviders};
use umineko_math::{Edwards, Integer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EdDSA {
    Ed25519,
    Ed448,
}

impl EdDSA {
    pub const ALL: [Self; 2] = [Self::Ed25519, Self::Ed448];
    /// The prefix that separates the contexts of Ed25519.
    pub const DOMAIN25519: &'static [u8] = b"SigEd25519 no Ed25519 collisions";
    /// The prefix that separates the contexts of Ed448.
    pub const DOMAIN448: &'static [u8] = b"SigEd448";
    pub const MAXIMUM_CONTEXT_SIZE: usize = 255;

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::Ed448 => "Ed448",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Ed25519" => Some(Self::Ed25519),
            "Ed448" => Some(Self::Ed448),
            _ => None,
        }
    }

    pub fn curve(&self) -> Edwards {
        match self {
            Self::Ed25519 => Edwards::ed25519(),
            Self::Ed448 => Edwards::ed448(),
        }
    }

    pub fn public_key_size(&self) -> usize {
        match self {
            Self::Ed25519 => 32,
            Self::Ed448 => 57,
        }
    }

    pub fn private_key_size(&self) -> usize {
        self.public_key_size()
    }

    pub fn signature_size(&self) -> usize {
        self.public_key_size() * 2
    }

    pub fn seed_size(&self) -> usize {
        self.public_key_size()
    }

    /// The length of the digest that the variant expands its private key into.
    pub fn digest_size(&self) -> usize {
        self.public_key_size() * 2
    }

    /// The prefix of one signature, which names the variant and the context.
    pub fn domain(&self, context: &[u8]) -> Vec<u8> {
        let mut domain = Vec::new();
        match self {
            Self::Ed25519 if context.is_empty() => return domain,
            Self::Ed25519 => domain.extend_from_slice(Self::DOMAIN25519),
            Self::Ed448 => domain.extend_from_slice(Self::DOMAIN448),
        }
        domain.push(0);
        domain.push(context.len() as u8);
        domain.extend_from_slice(context);
        domain
    }

    pub fn digest(&self, parts: &[&[u8]], digest: &mut [u8]) {
        match self {
            Self::Ed25519 => {
                let mut hash = SHA2_512::builtin();
                for part in parts {
                    hash.update(part);
                }
                digest.copy_from_slice(&hash.finalize()[..digest.len()]);
            }
            Self::Ed448 => {
                let mut hash = SHAKE256::builtin();
                for part in parts {
                    hash.update(part);
                }
                hash.finalize(digest);
            }
        }
    }

    /// The clamped scalar and the prefix that the private key expands into.
    pub fn expand(&self, private: &[u8]) -> (Integer, Vec<u8>) {
        let mut digest = alloc::vec![0; self.digest_size()];
        self.digest(&[private], &mut digest);
        let size = self.public_key_size();
        let mut scalar = digest[..size].to_vec();
        match self {
            Self::Ed25519 => {
                scalar[0] &= 248;
                scalar[31] &= 127;
                scalar[31] |= 64;
            }
            Self::Ed448 => {
                scalar[0] &= 252;
                scalar[55] |= 128;
                scalar[56] = 0;
            }
        }
        (Self::little(&scalar), digest[size..].to_vec())
    }

    /// The value of little endian bytes, which is how RFC 8032 writes every scalar.
    pub fn little(data: &[u8]) -> Integer {
        let mut bytes = data.to_vec();
        bytes.reverse();
        Integer::from_bytes(&bytes)
    }

    pub fn bytes(value: &Integer, length: usize) -> Vec<u8> {
        let mut bytes = value.to_bytes(length);
        bytes.reverse();
        bytes
    }

    pub fn request(&self) -> SignatureProviderRequest<'static> {
        SignatureProviderRequest::new(self.as_str())
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(EdDSAPrivateKey, EdDSAPublicKey), EdDSAError> {
        match SignatureProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((EdDSAPrivateKey { variant: *self, key: private }, EdDSAPublicKey { variant: *self, key: public })),
            None => {
                if seed.len() < self.seed_size() {
                    return Err(EdDSAError::Seed);
                }
                let private = EdDSAPrivateKey { variant: *self, key: seed[..self.seed_size()].to_vec() };
                let public = private.public_key();
                Ok((private, public))
            }
        }
    }
}

impl fmt::Display for EdDSA {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdDSAPrivateKey {
    variant: EdDSA,
    key: Vec<u8>,
}

impl EdDSAPrivateKey {
    pub fn decode(variant: EdDSA, data: &[u8]) -> Result<Self, EdDSAError> {
        match data.len() == variant.private_key_size() {
            true => Ok(Self { variant, key: data.to_vec() }),
            false => Err(EdDSAError::Encoding),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> EdDSA {
        self.variant
    }

    pub fn public_key(&self) -> EdDSAPublicKey {
        let request = self.variant.request();
        match SignatureProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.public_key(&request, &self.key)) {
            Some(key) => EdDSAPublicKey { variant: self.variant, key },
            None => {
                let curve = self.variant.curve();
                let (scalar, _) = self.variant.expand(&self.key);
                EdDSAPublicKey { variant: self.variant, key: curve.encode(&curve.multiply(&curve.generator(), &scalar)) }
            }
        }
    }

    pub fn sign(&self, message: &[u8], context: &[u8]) -> Result<EdDSASignature, EdDSAError> {
        if context.len() > EdDSA::MAXIMUM_CONTEXT_SIZE {
            return Err(EdDSAError::Length);
        }
        match SignatureProviders::sign(&self.variant.request().with_context(context), &self.key, message)? {
            Some(signature) => Ok(EdDSASignature { variant: self.variant, signature }),
            None => {
                let curve = self.variant.curve();
                let order = curve.order().modulus().clone();
                let size = self.variant.public_key_size();
                let (scalar, prefix) = self.variant.expand(&self.key);
                let domain = self.variant.domain(context);
                let mut digest = alloc::vec![0; self.variant.digest_size()];
                self.variant.digest(&[&domain, &prefix, message], &mut digest);
                let secret = EdDSA::little(&digest).modulo(&order).unwrap_or_else(Integer::zero);
                let commitment = curve.encode(&curve.multiply(&curve.generator(), &secret));
                let public = curve.encode(&curve.multiply(&curve.generator(), &scalar));
                self.variant.digest(&[&domain, &commitment, &public, message], &mut digest);
                let challenge = EdDSA::little(&digest).modulo(&order).unwrap_or_else(Integer::zero);
                let product = curve.order().multiply(&curve.order().residue(&challenge), &curve.order().residue(&scalar));
                let proof = curve.order().integer(&curve.order().add(&product, &curve.order().residue(&secret)));
                let mut signature = commitment;
                signature.extend_from_slice(&EdDSA::bytes(&proof, size));
                Ok(EdDSASignature { variant: self.variant, signature })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdDSAPublicKey {
    variant: EdDSA,
    key: Vec<u8>,
}

impl EdDSAPublicKey {
    pub fn decode(variant: EdDSA, data: &[u8]) -> Result<Self, EdDSAError> {
        if data.len() != variant.public_key_size() {
            return Err(EdDSAError::Encoding);
        }
        match variant.curve().decode(data) {
            Ok(_) => Ok(Self { variant, key: data.to_vec() }),
            Err(_) => Err(EdDSAError::Key),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> EdDSA {
        self.variant
    }

    pub fn verify(&self, message: &[u8], signature: &EdDSASignature, context: &[u8]) -> Result<(), EdDSAError> {
        if signature.variant != self.variant {
            return Err(EdDSAError::Variant);
        }
        if context.len() > EdDSA::MAXIMUM_CONTEXT_SIZE {
            return Err(EdDSAError::Length);
        }
        match SignatureProviders::verify(&self.variant.request().with_context(context), &self.key, message, &signature.signature)? {
            Some(()) => Ok(()),
            None => {
                let curve = self.variant.curve();
                let order = curve.order().modulus().clone();
                let size = self.variant.public_key_size();
                let (commitment, proof) = signature.signature.split_at(size);
                let proof = EdDSA::little(proof);
                if proof.compare(&order) != Ordering::Less {
                    return Err(EdDSAError::Verification);
                }
                let point = curve.decode(commitment).map_err(|_| EdDSAError::Verification)?;
                let public = curve.decode(&self.key).map_err(|_| EdDSAError::Key)?;
                let domain = self.variant.domain(context);
                let mut digest = alloc::vec![0; self.variant.digest_size()];
                self.variant.digest(&[&domain, commitment, &self.key, message], &mut digest);
                let challenge = EdDSA::little(&digest).modulo(&order).unwrap_or_else(Integer::zero);
                let left = curve.multiply(&curve.generator(), &proof);
                let right = curve.add(&point, &curve.multiply(&public, &challenge));
                match curve.equals(&left, &right) {
                    true => Ok(()),
                    false => Err(EdDSAError::Verification),
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdDSASignature {
    variant: EdDSA,
    signature: Vec<u8>,
}

impl EdDSASignature {
    pub fn decode(variant: EdDSA, data: &[u8]) -> Result<Self, EdDSAError> {
        match data.len() == variant.signature_size() {
            true => Ok(Self { variant, signature: data.to_vec() }),
            false => Err(EdDSAError::Length),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.signature.clone()
    }

    pub fn variant(&self) -> EdDSA {
        self.variant
    }
}
