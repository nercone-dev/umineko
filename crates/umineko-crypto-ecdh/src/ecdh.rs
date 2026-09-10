use alloc::vec::Vec;
use core::fmt;
use crate::errors::ECDHError;

use umineko_helpers::provider::{ExchangeProviderRequest, ExchangeProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ECDHCurve {
    X25519,
    X448,
    SECP256R1,
    SECP384R1,
    SECP521R1,
    SECT163K1,
    SECT163R1,
    SECT163R2,
    SECT193R1,
    SECT193R2,
    SECT233K1,
    SECT233R1,
    SECT239K1,
    SECT283K1,
    SECT283R1,
    SECT409K1,
    SECT409R1,
    SECT571K1,
    SECT571R1,
    SECP160K1,
    SECP160R1,
    SECP160R2,
    SECP192K1,
    SECP192R1,
    SECP224K1,
    SECP224R1,
    SECP256K1,
    BRAINPOOLP256R1,
    BRAINPOOLP384R1,
    BRAINPOOLP512R1,
    GC256A,
    GC256B,
    GC256C,
    GC256D,
    GC512A,
    GC512B,
    GC512C,
    SM2P256V1,
}

impl ECDHCurve {
    pub fn bits(&self) -> usize {
        match self {
            Self::X25519 => 255,
            Self::X448 => 448,
            Self::SECP256R1 => 256,
            Self::SECP384R1 => 384,
            Self::SECP521R1 => 521,
            Self::SECT163K1 | Self::SECT163R1 | Self::SECT163R2 => 163,
            Self::SECT193R1 | Self::SECT193R2 => 193,
            Self::SECT233K1 | Self::SECT233R1 => 233,
            Self::SECT239K1 => 239,
            Self::SECT283K1 | Self::SECT283R1 => 283,
            Self::SECT409K1 | Self::SECT409R1 => 409,
            Self::SECT571K1 | Self::SECT571R1 => 571,
            Self::SECP160K1 | Self::SECP160R1 | Self::SECP160R2 => 160,
            Self::SECP192K1 | Self::SECP192R1 => 192,
            Self::SECP224K1 | Self::SECP224R1 => 224,
            Self::SECP256K1 => 256,
            Self::BRAINPOOLP256R1 => 256,
            Self::BRAINPOOLP384R1 => 384,
            Self::BRAINPOOLP512R1 => 512,
            Self::GC256A | Self::GC256B | Self::GC256C | Self::GC256D => 256,
            Self::GC512A | Self::GC512B | Self::GC512C => 512,
            Self::SM2P256V1 => 256,
        }
    }

    pub fn public_key_size(&self) -> usize {
        todo!()
    }

    pub fn private_key_size(&self) -> usize {
        todo!()
    }

    pub fn shared_secret_size(&self) -> usize {
        todo!()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::X25519 => "X25519",
            Self::X448 => "X448",
            Self::SECP256R1 => "secp256r1",
            Self::SECP384R1 => "secp384r1",
            Self::SECP521R1 => "secp521r1",
            Self::SECT163K1 => "sect163k1",
            Self::SECT163R1 => "sect163r1",
            Self::SECT163R2 => "sect163r2",
            Self::SECT193R1 => "sect193r1",
            Self::SECT193R2 => "sect193r2",
            Self::SECT233K1 => "sect233k1",
            Self::SECT233R1 => "sect233r1",
            Self::SECT239K1 => "sect239k1",
            Self::SECT283K1 => "sect283k1",
            Self::SECT283R1 => "sect283r1",
            Self::SECT409K1 => "sect409k1",
            Self::SECT409R1 => "sect409r1",
            Self::SECT571K1 => "sect571k1",
            Self::SECT571R1 => "sect571r1",
            Self::SECP160K1 => "secp160k1",
            Self::SECP160R1 => "secp160r1",
            Self::SECP160R2 => "secp160r2",
            Self::SECP192K1 => "secp192k1",
            Self::SECP192R1 => "secp192r1",
            Self::SECP224K1 => "secp224k1",
            Self::SECP224R1 => "secp224r1",
            Self::SECP256K1 => "secp256k1",
            Self::BRAINPOOLP256R1 => "brainpoolP256r1",
            Self::BRAINPOOLP384R1 => "brainpoolP384r1",
            Self::BRAINPOOLP512R1 => "brainpoolP512r1",
            Self::GC256A => "GC256A",
            Self::GC256B => "GC256B",
            Self::GC256C => "GC256C",
            Self::GC256D => "GC256D",
            Self::GC512A => "GC512A",
            Self::GC512B => "GC512B",
            Self::GC512C => "GC512C",
            Self::SM2P256V1 => "sm2p256v1",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "X25519" => Some(Self::X25519),
            "X448" => Some(Self::X448),
            "secp256r1" => Some(Self::SECP256R1),
            "secp384r1" => Some(Self::SECP384R1),
            "secp521r1" => Some(Self::SECP521R1),
            "sect163k1" => Some(Self::SECT163K1),
            "sect163r1" => Some(Self::SECT163R1),
            "sect163r2" => Some(Self::SECT163R2),
            "sect193r1" => Some(Self::SECT193R1),
            "sect193r2" => Some(Self::SECT193R2),
            "sect233k1" => Some(Self::SECT233K1),
            "sect233r1" => Some(Self::SECT233R1),
            "sect239k1" => Some(Self::SECT239K1),
            "sect283k1" => Some(Self::SECT283K1),
            "sect283r1" => Some(Self::SECT283R1),
            "sect409k1" => Some(Self::SECT409K1),
            "sect409r1" => Some(Self::SECT409R1),
            "sect571k1" => Some(Self::SECT571K1),
            "sect571r1" => Some(Self::SECT571R1),
            "secp160k1" => Some(Self::SECP160K1),
            "secp160r1" => Some(Self::SECP160R1),
            "secp160r2" => Some(Self::SECP160R2),
            "secp192k1" => Some(Self::SECP192K1),
            "secp192r1" => Some(Self::SECP192R1),
            "secp224k1" => Some(Self::SECP224K1),
            "secp224r1" => Some(Self::SECP224R1),
            "secp256k1" => Some(Self::SECP256K1),
            "brainpoolP256r1" => Some(Self::BRAINPOOLP256R1),
            "brainpoolP384r1" => Some(Self::BRAINPOOLP384R1),
            "brainpoolP512r1" => Some(Self::BRAINPOOLP512R1),
            "GC256A" => Some(Self::GC256A),
            "GC256B" => Some(Self::GC256B),
            "GC256C" => Some(Self::GC256C),
            "GC256D" => Some(Self::GC256D),
            "GC512A" => Some(Self::GC512A),
            "GC512B" => Some(Self::GC512B),
            "GC512C" => Some(Self::GC512C),
            "sm2p256v1" => Some(Self::SM2P256V1),
            _ => None,
        }
    }
}

impl fmt::Display for ECDHCurve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ECDHBasis {
    Trinomial(u16),
    Pentanomial(u16, u16, u16),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ECDHField {
    Prime(Vec<u8>),
    Characteristic2 { degree: u16, basis: ECDHBasis },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ECDHParameters {
    field: ECDHField,
    a: Vec<u8>,
    b: Vec<u8>,
    base: Vec<u8>,
    order: Vec<u8>,
    cofactor: Vec<u8>,
    encoded: Vec<u8>,
}

impl ECDHParameters {
    pub fn new(field: ECDHField, a: &[u8], b: &[u8], base: &[u8], order: &[u8], cofactor: &[u8]) -> Result<Self, ECDHError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<Self, ECDHError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.encoded.clone()
    }

    pub fn field(&self) -> &ECDHField {
        &self.field
    }

    pub fn a(&self) -> &[u8] {
        &self.a
    }

    pub fn b(&self) -> &[u8] {
        &self.b
    }

    pub fn base(&self) -> &[u8] {
        &self.base
    }

    pub fn order(&self) -> &[u8] {
        &self.order
    }

    pub fn cofactor(&self) -> &[u8] {
        &self.cofactor
    }

    pub fn bits(&self) -> usize {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ECDH {
    Curve(ECDHCurve),
    Parameters(ECDHParameters),
}

impl ECDH {
    pub const NAME: &'static str = "ECDH";

    pub fn bits(&self) -> usize {
        match self {
            Self::Curve(curve) => curve.bits(),
            Self::Parameters(parameters) => parameters.bits(),
        }
    }

    pub fn request(&self) -> ExchangeProviderRequest<'_> {
        match self {
            Self::Curve(curve) => ExchangeProviderRequest::new(curve.as_str()),
            Self::Parameters(parameters) => ExchangeProviderRequest::new(Self::NAME).with_parameters(&parameters.encoded),
        }
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(ECDHPrivateKey, ECDHPublicKey), ECDHError> {
        match ExchangeProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((ECDHPrivateKey { domain: self.clone(), key: private }, ECDHPublicKey { domain: self.clone(), key: public })),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDHPrivateKey {
    domain: ECDH,
    key: Vec<u8>,
}

impl ECDHPrivateKey {
    pub fn decode(domain: ECDH, data: &[u8]) -> Result<Self, ECDHError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn domain(&self) -> &ECDH {
        &self.domain
    }

    pub fn public_key(&self) -> ECDHPublicKey {
        let request = self.domain.request();
        match ExchangeProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.public_key(&request, &self.key)) {
            Some(key) => ECDHPublicKey { domain: self.domain.clone(), key },
            None => todo!(),
        }
    }

    pub fn exchange(&self, peer: &ECDHPublicKey) -> Result<ECDHSharedSecret, ECDHError> {
        match ExchangeProviders::exchange(&self.domain.request(), &self.key, &peer.key)? {
            Some(secret) => Ok(ECDHSharedSecret { secret }),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDHPublicKey {
    domain: ECDH,
    key: Vec<u8>,
}

impl ECDHPublicKey {
    pub fn decode(domain: ECDH, data: &[u8]) -> Result<Self, ECDHError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn domain(&self) -> &ECDH {
        &self.domain
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDHSharedSecret {
    secret: Vec<u8>,
}

impl ECDHSharedSecret {
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
