use alloc::vec::Vec;
use core::fmt;
use crate::errors::ECDHError;

use umineko_helpers::provider::{ExchangeProviderRequest, ExchangeProviders};
use umineko_math::{Integer, Ladder, Weierstrass};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ECDH {
    X25519,
    X448,
    SECP256R1,
    SECP384R1,
    SECP521R1,
}

impl ECDH {
    pub const ALL: [Self; 5] = [Self::X25519, Self::X448, Self::SECP256R1, Self::SECP384R1, Self::SECP521R1];

    /// The size of one coordinate, which the encodings build upon.
    pub fn size(&self) -> usize {
        match self {
            Self::X25519 => 32,
            Self::X448 => 56,
            Self::SECP256R1 => 32,
            Self::SECP384R1 => 48,
            Self::SECP521R1 => 66,
        }
    }

    pub fn montgomery(&self) -> bool {
        matches!(self, Self::X25519 | Self::X448)
    }

    pub fn ladder(&self) -> Option<Ladder> {
        Ladder::from_name(self.as_str())
    }

    pub fn curve(&self) -> Option<Weierstrass> {
        Weierstrass::from_name(self.as_str())
    }

    pub fn public_key_size(&self) -> usize {
        match self.montgomery() {
            true => self.size(),
            false => 1 + self.size() * 2,
        }
    }

    pub fn private_key_size(&self) -> usize {
        self.size()
    }

    pub fn shared_secret_size(&self) -> usize {
        self.size()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::X25519 => "X25519",
            Self::X448 => "X448",
            Self::SECP256R1 => "secp256r1",
            Self::SECP384R1 => "secp384r1",
            Self::SECP521R1 => "secp521r1",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "X25519" => Some(Self::X25519),
            "X448" => Some(Self::X448),
            "secp256r1" => Some(Self::SECP256R1),
            "secp384r1" => Some(Self::SECP384R1),
            "secp521r1" => Some(Self::SECP521R1),
            _ => None,
        }
    }

    pub fn request(&self) -> ExchangeProviderRequest<'static> {
        ExchangeProviderRequest::new(self.as_str())
    }

    /// A private key drawn from a seed of at least the private key size.
    pub fn generate(&self, seed: &[u8]) -> Result<(ECDHPrivateKey, ECDHPublicKey), ECDHError> {
        match ExchangeProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((ECDHPrivateKey { curve: *self, key: private }, ECDHPublicKey { curve: *self, key: public })),
            None => {
                if seed.len() < self.private_key_size() {
                    return Err(ECDHError::Seed);
                }
                let key = match self.montgomery() {
                    true => seed[..self.private_key_size()].to_vec(),
                    false => {
                        let curve = self.curve().ok_or(ECDHError::Curve)?;
                        let order = curve.order().modulus().subtract(&Integer::one());
                        let scalar = Integer::from_bytes(seed).modulo(&order).unwrap_or_else(Integer::zero).add(&Integer::one());
                        scalar.to_bytes(self.private_key_size())
                    }
                };
                let private = ECDHPrivateKey { curve: *self, key };
                let public = private.public_key();
                Ok((private, public))
            }
        }
    }
}

impl fmt::Display for ECDH {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDHPrivateKey {
    curve: ECDH,
    key: Vec<u8>,
}

impl ECDHPrivateKey {
    pub fn decode(curve: ECDH, data: &[u8]) -> Result<Self, ECDHError> {
        if data.len() != curve.private_key_size() {
            return Err(ECDHError::Encoding);
        }
        if !curve.montgomery() {
            let scalar = Integer::from_bytes(data);
            let order = curve.curve().ok_or(ECDHError::Curve)?.order().modulus().clone();
            if scalar.is_zero() || scalar.compare(&order) != core::cmp::Ordering::Less {
                return Err(ECDHError::Key);
            }
        }
        Ok(Self { curve, key: data.to_vec() })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn curve(&self) -> ECDH {
        self.curve
    }

    pub fn public_key(&self) -> ECDHPublicKey {
        let request = self.curve.request();
        match ExchangeProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.public_key(&request, &self.key)) {
            Some(key) => ECDHPublicKey { curve: self.curve, key },
            None => ECDHPublicKey { curve: self.curve, key: self.derive() },
        }
    }

    /// The public key of the built in arithmetic, which is a coordinate or an uncompressed point.
    pub fn derive(&self) -> Vec<u8> {
        match self.curve.ladder() {
            Some(ladder) => ladder.multiply_base(&self.key).unwrap_or_default(),
            None => match self.curve.curve() {
                Some(curve) => curve.encode(&curve.multiply(&curve.generator(), &Integer::from_bytes(&self.key)), false),
                None => Vec::new(),
            },
        }
    }

    pub fn exchange(&self, peer: &ECDHPublicKey) -> Result<ECDHSharedSecret, ECDHError> {
        if peer.curve != self.curve {
            return Err(ECDHError::Curve);
        }
        match ExchangeProviders::exchange(&self.curve.request(), &self.key, &peer.key)? {
            Some(secret) => Ok(ECDHSharedSecret { secret }),
            None => {
                let secret = match self.curve.ladder() {
                    Some(ladder) => ladder.multiply(&self.key, &peer.key).map_err(|_| ECDHError::Point)?,
                    None => {
                        let curve = self.curve.curve().ok_or(ECDHError::Curve)?;
                        let point = curve.decode(&peer.key).map_err(|_| ECDHError::Point)?;
                        let shared = curve.multiply(&point, &Integer::from_bytes(&self.key));
                        curve.affine(&shared).ok_or(ECDHError::SharedSecret)?.0.to_bytes(self.curve.shared_secret_size())
                    }
                };
                match secret.iter().all(|byte| *byte == 0) {
                    true => Err(ECDHError::SharedSecret),
                    false => Ok(ECDHSharedSecret { secret }),
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECDHPublicKey {
    curve: ECDH,
    key: Vec<u8>,
}

impl ECDHPublicKey {
    pub fn decode(curve: ECDH, data: &[u8]) -> Result<Self, ECDHError> {
        match curve.montgomery() {
            true if data.len() == curve.public_key_size() => Ok(Self { curve, key: data.to_vec() }),
            true => Err(ECDHError::Encoding),
            false => {
                let point = curve.curve().ok_or(ECDHError::Curve)?;
                let decoded = point.decode(data).map_err(|_| ECDHError::Point)?;
                match decoded.is_identity() {
                    true => Err(ECDHError::Point),
                    false => Ok(Self { curve, key: point.encode(&decoded, false) }),
                }
            }
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn curve(&self) -> ECDH {
        self.curve
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
