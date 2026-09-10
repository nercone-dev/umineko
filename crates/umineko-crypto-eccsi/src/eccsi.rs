use alloc::vec::Vec;
use core::fmt;
use crate::errors::ECCSIError;

use umineko_helpers::provider::{SignatureProviderRequest, SignatureProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ECCSI {
    P256,
}

impl ECCSI {
    pub const ALL: [Self; 1] = [Self::P256];
    pub const UNCOMPRESSED: u8 = 0x04;

    pub fn curve_name(&self) -> &'static str {
        match self {
            Self::P256 => "secp256r1",
        }
    }

    pub fn hash_name(&self) -> &'static str {
        match self {
            Self::P256 => "SHA-256",
        }
    }

    pub fn security_bits(&self) -> usize {
        match self {
            Self::P256 => 256,
        }
    }

    pub fn field_size(&self) -> usize {
        self.security_bits().div_ceil(8)
    }

    pub fn point_size(&self) -> usize {
        2 * self.field_size() + 1
    }

    pub fn master_key_size(&self) -> usize {
        self.field_size()
    }

    pub fn public_key_size(&self) -> usize {
        self.point_size()
    }

    pub fn secret_signing_key_size(&self) -> usize {
        self.field_size()
    }

    pub fn public_validation_token_size(&self) -> usize {
        self.point_size()
    }

    pub fn signature_size(&self) -> usize {
        2 * self.field_size() + self.point_size()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::P256 => "ECCSI-P256",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|variant| variant.as_str() == name)
    }

    pub fn request(&self) -> SignatureProviderRequest<'static> {
        SignatureProviderRequest::new(self.as_str())
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(ECCSIMasterKey, ECCSIPublicKey), ECCSIError> {
        match SignatureProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((ECCSIMasterKey::decode(*self, &private)?, ECCSIPublicKey::decode(*self, &public)?)),
            None => todo!(),
        }
    }
}

impl fmt::Display for ECCSI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECCSIMasterKey {
    variant: ECCSI,
    key: Vec<u8>,
}

impl ECCSIMasterKey {
    pub fn decode(variant: ECCSI, data: &[u8]) -> Result<Self, ECCSIError> {
        if data.len() != variant.master_key_size() {
            return Err(ECCSIError::Length);
        }
        Ok(Self { variant, key: data.to_vec() })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> ECCSI {
        self.variant
    }

    pub fn public_key(&self) -> Result<ECCSIPublicKey, ECCSIError> {
        match SignatureProviders::public_key(&self.variant.request(), &self.key)? {
            Some(key) => ECCSIPublicKey::decode(self.variant, &key),
            None => todo!(),
        }
    }

    pub fn issue(&self, identity: &[u8], seed: &[u8]) -> Result<ECCSISigningKey, ECCSIError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECCSIPublicKey {
    variant: ECCSI,
    key: Vec<u8>,
}

impl ECCSIPublicKey {
    pub fn decode(variant: ECCSI, data: &[u8]) -> Result<Self, ECCSIError> {
        if data.len() != variant.public_key_size() {
            return Err(ECCSIError::Length);
        }
        if data[0] != ECCSI::UNCOMPRESSED {
            return Err(ECCSIError::Encoding);
        }
        Ok(Self { variant, key: data.to_vec() })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> ECCSI {
        self.variant
    }

    pub fn verify(&self, identity: &[u8], message: &[u8], signature: &ECCSISignature) -> Result<(), ECCSIError> {
        if signature.variant != self.variant {
            return Err(ECCSIError::Key);
        }
        match SignatureProviders::verify(&self.variant.request().with_context(identity), &self.key, message, &signature.signature)? {
            Some(()) => Ok(()),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECCSISigningKey {
    variant: ECCSI,
    secret_signing_key: Vec<u8>,
    public_validation_token: Vec<u8>,
}

impl ECCSISigningKey {
    pub fn decode(variant: ECCSI, secret_signing_key: &[u8], public_validation_token: &[u8]) -> Result<Self, ECCSIError> {
        if secret_signing_key.len() != variant.secret_signing_key_size() || public_validation_token.len() != variant.public_validation_token_size() {
            return Err(ECCSIError::Length);
        }
        if public_validation_token[0] != ECCSI::UNCOMPRESSED {
            return Err(ECCSIError::Encoding);
        }
        Ok(Self { variant, secret_signing_key: secret_signing_key.to_vec(), public_validation_token: public_validation_token.to_vec() })
    }

    pub fn secret_signing_key(&self) -> &[u8] {
        &self.secret_signing_key
    }

    pub fn public_validation_token(&self) -> &[u8] {
        &self.public_validation_token
    }

    pub fn variant(&self) -> ECCSI {
        self.variant
    }

    pub fn validate(&self, identity: &[u8], public: &ECCSIPublicKey) -> Result<(), ECCSIError> {
        todo!()
    }

    pub fn sign(&self, public: &ECCSIPublicKey, identity: &[u8], message: &[u8], seed: &[u8]) -> Result<ECCSISignature, ECCSIError> {
        if public.variant != self.variant {
            return Err(ECCSIError::Key);
        }
        let private = [self.secret_signing_key.as_slice(), &self.public_validation_token, &public.key].concat();
        match SignatureProviders::sign(&self.variant.request().with_context(identity).with_seed(seed), &private, message)? {
            Some(signature) => ECCSISignature::decode(self.variant, &signature),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ECCSISignature {
    variant: ECCSI,
    signature: Vec<u8>,
}

impl ECCSISignature {
    pub fn decode(variant: ECCSI, data: &[u8]) -> Result<Self, ECCSIError> {
        if data.len() != variant.signature_size() {
            return Err(ECCSIError::Length);
        }
        if data[2 * variant.field_size()] != ECCSI::UNCOMPRESSED {
            return Err(ECCSIError::Encoding);
        }
        Ok(Self { variant, signature: data.to_vec() })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.signature.clone()
    }

    pub fn variant(&self) -> ECCSI {
        self.variant
    }

    pub fn r(&self) -> &[u8] {
        &self.signature[..self.variant.field_size()]
    }

    pub fn s(&self) -> &[u8] {
        &self.signature[self.variant.field_size()..2 * self.variant.field_size()]
    }

    pub fn public_validation_token(&self) -> &[u8] {
        &self.signature[2 * self.variant.field_size()..]
    }
}
