use alloc::vec::Vec;
use core::fmt;
use crate::errors::HybridKEXError;

use umineko_crypto_ecdh::{ECDH, ECDHPrivateKey, ECDHPublicKey};
use umineko_crypto_mlkem::{MLKEM, MLKEMCiphertext, MLKEMPrivateKey, MLKEMPublicKey};

/// A key exchange that runs one curve and one lattice side by side, joining both shared secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HybridKEX {
    #[cfg(feature = "x25519mlkem768")]
    X25519MLKEM768,
    #[cfg(feature = "secp256r1mlkem768")]
    SECP256R1MLKEM768,
    #[cfg(feature = "secp384r1mlkem1024")]
    SECP384R1MLKEM1024,
}

impl HybridKEX {
    pub const ALL: [Self; 3] = [Self::X25519MLKEM768, Self::SECP256R1MLKEM768, Self::SECP384R1MLKEM1024];

    pub fn ecdh(&self) -> ECDH {
        match self {
            Self::X25519MLKEM768 => ECDH::X25519,
            Self::SECP256R1MLKEM768 => ECDH::SECP256R1,
            Self::SECP384R1MLKEM1024 => ECDH::SECP384R1,
        }
    }

    pub fn mlkem(&self) -> MLKEM {
        match self {
            Self::X25519MLKEM768 | Self::SECP256R1MLKEM768 => MLKEM::V768,
            Self::SECP384R1MLKEM1024 => MLKEM::V1024,
        }
    }

    /// Whether the lattice half comes first, which only the exchange over Curve25519 does.
    pub fn lattice_first(&self) -> bool {
        matches!(self, Self::X25519MLKEM768)
    }

    pub fn public_key_size(&self) -> usize {
        self.ecdh().public_key_size() + self.mlkem().public_key_size()
    }

    pub fn private_key_size(&self) -> usize {
        self.ecdh().private_key_size() + self.mlkem().private_key_size()
    }

    pub fn ciphertext_size(&self) -> usize {
        self.ecdh().public_key_size() + self.mlkem().ciphertext_size()
    }

    pub fn shared_secret_size(&self) -> usize {
        self.ecdh().shared_secret_size() + self.mlkem().shared_secret_size()
    }

    pub fn seed_size(&self) -> usize {
        self.ecdh().private_key_size() + self.mlkem().seed_size()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::X25519MLKEM768 => "X25519MLKEM768",
            Self::SECP256R1MLKEM768 => "SecP256r1MLKEM768",
            Self::SECP384R1MLKEM1024 => "SecP384r1MLKEM1024",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "X25519MLKEM768" => Some(Self::X25519MLKEM768),
            "SecP256r1MLKEM768" => Some(Self::SECP256R1MLKEM768),
            "SecP384r1MLKEM1024" => Some(Self::SECP384R1MLKEM1024),
            _ => None,
        }
    }

    /// The two halves of a message, in the order that the variant puts them.
    pub fn split<'a>(&self, data: &'a [u8], curve: usize, lattice: usize) -> Result<(&'a [u8], &'a [u8]), HybridKEXError> {
        if data.len() != curve + lattice {
            return Err(HybridKEXError::Length);
        }
        match self.lattice_first() {
            true => Ok((&data[lattice..], &data[..lattice])),
            false => Ok((&data[..curve], &data[curve..])),
        }
    }

    pub fn join(&self, curve: &[u8], lattice: &[u8]) -> Vec<u8> {
        let mut joined = Vec::with_capacity(curve.len() + lattice.len());
        match self.lattice_first() {
            true => {
                joined.extend_from_slice(lattice);
                joined.extend_from_slice(curve);
            }
            false => {
                joined.extend_from_slice(curve);
                joined.extend_from_slice(lattice);
            }
        }
        joined
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(HybridKEXPrivateKey, HybridKEXPublicKey), HybridKEXError> {
        if seed.len() < self.seed_size() {
            return Err(HybridKEXError::Length);
        }
        let (curve, lattice) = seed.split_at(self.ecdh().private_key_size());
        let (ecdh, ecdh_public) = self.ecdh().generate(curve)?;
        let (mlkem, mlkem_public) = self.mlkem().generate(lattice)?;
        let private = HybridKEXPrivateKey { variant: *self, ecdh, mlkem };
        let public = HybridKEXPublicKey { variant: *self, ecdh: ecdh_public, mlkem: mlkem_public };
        Ok((private, public))
    }
}

impl fmt::Display for HybridKEX {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridKEXPrivateKey {
    variant: HybridKEX,
    ecdh: ECDHPrivateKey,
    mlkem: MLKEMPrivateKey,
}

impl HybridKEXPrivateKey {
    pub fn decode(variant: HybridKEX, data: &[u8]) -> Result<Self, HybridKEXError> {
        let (curve, lattice) = variant.split(data, variant.ecdh().private_key_size(), variant.mlkem().private_key_size())?;
        Ok(Self { variant, ecdh: ECDHPrivateKey::decode(variant.ecdh(), curve)?, mlkem: MLKEMPrivateKey::decode(variant.mlkem(), lattice)? })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.variant.join(&self.ecdh.encode(), &self.mlkem.encode())
    }

    pub fn variant(&self) -> HybridKEX {
        self.variant
    }

    pub fn public_key(&self) -> HybridKEXPublicKey {
        HybridKEXPublicKey { variant: self.variant, ecdh: self.ecdh.public_key(), mlkem: self.mlkem.public_key() }
    }

    pub fn decapsulate(&self, ciphertext: &HybridKEXCiphertext) -> Result<HybridKEXSharedSecret, HybridKEXError> {
        if ciphertext.variant != self.variant {
            return Err(HybridKEXError::Variant);
        }
        let curve = self.ecdh.exchange(&ciphertext.ecdh)?;
        let lattice = self.mlkem.decapsulate(&ciphertext.mlkem)?;
        Ok(HybridKEXSharedSecret { secret: self.variant.join(curve.as_slice(), lattice.as_slice()) })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridKEXPublicKey {
    variant: HybridKEX,
    ecdh: ECDHPublicKey,
    mlkem: MLKEMPublicKey,
}

impl HybridKEXPublicKey {
    pub fn decode(variant: HybridKEX, data: &[u8]) -> Result<Self, HybridKEXError> {
        let (curve, lattice) = variant.split(data, variant.ecdh().public_key_size(), variant.mlkem().public_key_size())?;
        Ok(Self { variant, ecdh: ECDHPublicKey::decode(variant.ecdh(), curve)?, mlkem: MLKEMPublicKey::decode(variant.mlkem(), lattice)? })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.variant.join(&self.ecdh.encode(), &self.mlkem.encode())
    }

    pub fn variant(&self) -> HybridKEX {
        self.variant
    }

    /// The ciphertext of both halves, which carries one ephemeral curve key of its own.
    pub fn encapsulate(&self, seed: &[u8]) -> Result<(HybridKEXCiphertext, HybridKEXSharedSecret), HybridKEXError> {
        if seed.len() < self.variant.ecdh().private_key_size() + MLKEM::SEED_SIZE {
            return Err(HybridKEXError::Length);
        }
        let (curve, lattice) = seed.split_at(self.variant.ecdh().private_key_size());
        let (ephemeral, public) = self.variant.ecdh().generate(curve)?;
        let shared = ephemeral.exchange(&self.ecdh)?;
        let (ciphertext, secret) = self.mlkem.encapsulate(lattice)?;
        let joined = self.variant.join(shared.as_slice(), secret.as_slice());
        Ok((HybridKEXCiphertext { variant: self.variant, ecdh: public, mlkem: ciphertext }, HybridKEXSharedSecret { secret: joined }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridKEXCiphertext {
    variant: HybridKEX,
    ecdh: ECDHPublicKey,
    mlkem: MLKEMCiphertext,
}

impl HybridKEXCiphertext {
    pub fn decode(variant: HybridKEX, data: &[u8]) -> Result<Self, HybridKEXError> {
        let (curve, lattice) = variant.split(data, variant.ecdh().public_key_size(), variant.mlkem().ciphertext_size())?;
        Ok(Self { variant, ecdh: ECDHPublicKey::decode(variant.ecdh(), curve)?, mlkem: MLKEMCiphertext::decode(variant.mlkem(), lattice)? })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.variant.join(&self.ecdh.encode(), &self.mlkem.encode())
    }

    pub fn variant(&self) -> HybridKEX {
        self.variant
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridKEXSharedSecret {
    secret: Vec<u8>,
}

impl HybridKEXSharedSecret {
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
