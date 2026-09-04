use alloc::vec::Vec;
use core::fmt;
use crate::errors::HybridKEXError;

use umineko_crypto_ecdh::{ECDH, ECDHPrivateKey, ECDHPublicKey};
use umineko_crypto_mlkem::{MLKEM, MLKEMPrivateKey, MLKEMPublicKey, MLKEMCiphertext};

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
    pub fn ecdh(&self) -> ECDH {
        todo!()
    }

    pub fn mlkem(&self) -> MLKEM {
        todo!()
    }

    pub fn public_key_size(&self) -> usize {
        todo!()
    }

    pub fn private_key_size(&self) -> usize {
        todo!()
    }

    pub fn ciphertext_size(&self) -> usize {
        todo!()
    }

    pub fn shared_secret_size(&self) -> usize {
        todo!()
    }

    pub fn as_str(&self) -> &'static str {
        todo!()
    }

    pub fn from_name(name: &str) -> Option<Self> {
        todo!()
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(HybridKEXPrivateKey, HybridKEXPublicKey), HybridKEXError> {
        todo!()
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
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }

    pub fn variant(&self) -> HybridKEX {
        self.variant
    }

    pub fn public_key(&self) -> HybridKEXPublicKey {
        todo!()
    }

    pub fn decapsulate(&self, ciphertext: &HybridKEXCiphertext) -> Result<HybridKEXSharedSecret, HybridKEXError> {
        todo!()
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
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }

    pub fn variant(&self) -> HybridKEX {
        self.variant
    }

    pub fn encapsulate(&self, seed: &[u8]) -> Result<(HybridKEXCiphertext, HybridKEXSharedSecret), HybridKEXError> {
        todo!()
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
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        todo!()
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
        todo!()
    }

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
