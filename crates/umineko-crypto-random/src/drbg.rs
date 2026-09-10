use core::fmt;
use crate::errors::RandomError;

use umineko_helpers::provider::{ProviderBackend, RandomProvider, RandomProviderRequest, RandomProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DRBGHash {
    SHA1,
    SHA2_224,
    SHA2_512_224,
    SHA2_256,
    SHA2_512_256,
    SHA2_384,
    SHA2_512,
}

impl DRBGHash {
    pub const ALL: [Self; 7] = [Self::SHA1, Self::SHA2_224, Self::SHA2_512_224, Self::SHA2_256, Self::SHA2_512_256, Self::SHA2_384, Self::SHA2_512];

    pub fn output_size(&self) -> usize {
        match self {
            Self::SHA1 => 20,
            Self::SHA2_224 => 28,
            Self::SHA2_512_224 => 28,
            Self::SHA2_256 => 32,
            Self::SHA2_512_256 => 32,
            Self::SHA2_384 => 48,
            Self::SHA2_512 => 64,
        }
    }

    pub fn seed_size(&self) -> usize {
        match self {
            Self::SHA1 | Self::SHA2_224 | Self::SHA2_512_224 | Self::SHA2_256 | Self::SHA2_512_256 => 55,
            Self::SHA2_384 | Self::SHA2_512 => 111,
        }
    }

    pub fn security_strength(&self) -> usize {
        match self {
            Self::SHA1 => 128,
            Self::SHA2_224 | Self::SHA2_512_224 => 192,
            Self::SHA2_256 | Self::SHA2_512_256 | Self::SHA2_384 | Self::SHA2_512 => 256,
        }
    }

    pub fn hash_name(&self) -> &'static str {
        match self {
            Self::SHA1 => "SHA-1",
            Self::SHA2_224 => "SHA-224",
            Self::SHA2_512_224 => "SHA-512/224",
            Self::SHA2_256 => "SHA-256",
            Self::SHA2_512_256 => "SHA-512/256",
            Self::SHA2_384 => "SHA-384",
            Self::SHA2_512 => "SHA-512",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DRBGCipher {
    TDEA,
    AES128,
    AES192,
    AES256,
}

impl DRBGCipher {
    pub const ALL: [Self; 4] = [Self::TDEA, Self::AES128, Self::AES192, Self::AES256];

    pub fn block_size(&self) -> usize {
        match self {
            Self::TDEA => 8,
            Self::AES128 | Self::AES192 | Self::AES256 => 16,
        }
    }

    pub fn key_size(&self) -> usize {
        match self {
            Self::TDEA => 21,
            Self::AES128 => 16,
            Self::AES192 => 24,
            Self::AES256 => 32,
        }
    }

    pub fn seed_size(&self) -> usize {
        self.block_size() + self.key_size()
    }

    pub fn security_strength(&self) -> usize {
        match self {
            Self::TDEA => 112,
            Self::AES128 => 128,
            Self::AES192 => 192,
            Self::AES256 => 256,
        }
    }

    pub fn cipher_name(&self) -> &'static str {
        match self {
            Self::TDEA => "TDEA",
            Self::AES128 => "AES-128",
            Self::AES192 => "AES-192",
            Self::AES256 => "AES-256",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DRBG {
    Hash(DRBGHash),
    HMAC(DRBGHash),
    CTR { cipher: DRBGCipher, derivation: bool },
}

impl DRBG {
    pub const ALL: [Self; 22] = [
        Self::Hash(DRBGHash::SHA1),
        Self::Hash(DRBGHash::SHA2_224),
        Self::Hash(DRBGHash::SHA2_512_224),
        Self::Hash(DRBGHash::SHA2_256),
        Self::Hash(DRBGHash::SHA2_512_256),
        Self::Hash(DRBGHash::SHA2_384),
        Self::Hash(DRBGHash::SHA2_512),
        Self::HMAC(DRBGHash::SHA1),
        Self::HMAC(DRBGHash::SHA2_224),
        Self::HMAC(DRBGHash::SHA2_512_224),
        Self::HMAC(DRBGHash::SHA2_256),
        Self::HMAC(DRBGHash::SHA2_512_256),
        Self::HMAC(DRBGHash::SHA2_384),
        Self::HMAC(DRBGHash::SHA2_512),
        Self::CTR { cipher: DRBGCipher::TDEA, derivation: true },
        Self::CTR { cipher: DRBGCipher::TDEA, derivation: false },
        Self::CTR { cipher: DRBGCipher::AES128, derivation: true },
        Self::CTR { cipher: DRBGCipher::AES128, derivation: false },
        Self::CTR { cipher: DRBGCipher::AES192, derivation: true },
        Self::CTR { cipher: DRBGCipher::AES192, derivation: false },
        Self::CTR { cipher: DRBGCipher::AES256, derivation: true },
        Self::CTR { cipher: DRBGCipher::AES256, derivation: false },
    ];
    pub const SECURITY_STRENGTHS: [usize; 4] = [112, 128, 192, 256];
    pub const MAXIMUM_INPUT_SIZE: u64 = 1 << 32;

    pub fn security_strength(&self) -> usize {
        match self {
            Self::Hash(hash) | Self::HMAC(hash) => hash.security_strength(),
            Self::CTR { cipher, .. } => cipher.security_strength(),
        }
    }

    pub fn seed_size(&self) -> Option<usize> {
        match self {
            Self::Hash(hash) => Some(hash.seed_size()),
            Self::HMAC(_) => None,
            Self::CTR { cipher, .. } => Some(cipher.seed_size()),
        }
    }

    pub fn nonce_required(&self) -> bool {
        !matches!(self, Self::CTR { derivation: false, .. })
    }

    pub fn minimum_entropy_size(&self, security_strength: usize) -> usize {
        match self {
            Self::CTR { cipher, derivation: false } => cipher.seed_size(),
            Self::Hash(_) | Self::HMAC(_) | Self::CTR { derivation: true, .. } => security_strength.div_ceil(8),
        }
    }

    pub fn maximum_entropy_size(&self) -> u64 {
        match self {
            Self::CTR { cipher, derivation: false } => cipher.seed_size() as u64,
            Self::Hash(_) | Self::HMAC(_) | Self::CTR { derivation: true, .. } => Self::MAXIMUM_INPUT_SIZE,
        }
    }

    pub fn maximum_input_size(&self) -> u64 {
        match self {
            Self::CTR { cipher, derivation: false } => cipher.seed_size() as u64,
            Self::Hash(_) | Self::HMAC(_) | Self::CTR { derivation: true, .. } => Self::MAXIMUM_INPUT_SIZE,
        }
    }

    pub fn maximum_request_size(&self) -> usize {
        match self {
            Self::CTR { cipher: DRBGCipher::TDEA, .. } => 1 << 10,
            Self::Hash(_) | Self::HMAC(_) | Self::CTR { .. } => 1 << 16,
        }
    }

    pub fn reseed_interval(&self) -> u64 {
        match self {
            Self::CTR { cipher: DRBGCipher::TDEA, .. } => 1 << 32,
            Self::Hash(_) | Self::HMAC(_) | Self::CTR { .. } => 1 << 48,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hash(DRBGHash::SHA1) => "Hash_DRBG-SHA-1",
            Self::Hash(DRBGHash::SHA2_224) => "Hash_DRBG-SHA-224",
            Self::Hash(DRBGHash::SHA2_512_224) => "Hash_DRBG-SHA-512/224",
            Self::Hash(DRBGHash::SHA2_256) => "Hash_DRBG-SHA-256",
            Self::Hash(DRBGHash::SHA2_512_256) => "Hash_DRBG-SHA-512/256",
            Self::Hash(DRBGHash::SHA2_384) => "Hash_DRBG-SHA-384",
            Self::Hash(DRBGHash::SHA2_512) => "Hash_DRBG-SHA-512",
            Self::HMAC(DRBGHash::SHA1) => "HMAC_DRBG-SHA-1",
            Self::HMAC(DRBGHash::SHA2_224) => "HMAC_DRBG-SHA-224",
            Self::HMAC(DRBGHash::SHA2_512_224) => "HMAC_DRBG-SHA-512/224",
            Self::HMAC(DRBGHash::SHA2_256) => "HMAC_DRBG-SHA-256",
            Self::HMAC(DRBGHash::SHA2_512_256) => "HMAC_DRBG-SHA-512/256",
            Self::HMAC(DRBGHash::SHA2_384) => "HMAC_DRBG-SHA-384",
            Self::HMAC(DRBGHash::SHA2_512) => "HMAC_DRBG-SHA-512",
            Self::CTR { cipher: DRBGCipher::TDEA, derivation: true } => "CTR_DRBG-TDEA-DF",
            Self::CTR { cipher: DRBGCipher::TDEA, derivation: false } => "CTR_DRBG-TDEA",
            Self::CTR { cipher: DRBGCipher::AES128, derivation: true } => "CTR_DRBG-AES-128-DF",
            Self::CTR { cipher: DRBGCipher::AES128, derivation: false } => "CTR_DRBG-AES-128",
            Self::CTR { cipher: DRBGCipher::AES192, derivation: true } => "CTR_DRBG-AES-192-DF",
            Self::CTR { cipher: DRBGCipher::AES192, derivation: false } => "CTR_DRBG-AES-192",
            Self::CTR { cipher: DRBGCipher::AES256, derivation: true } => "CTR_DRBG-AES-256-DF",
            Self::CTR { cipher: DRBGCipher::AES256, derivation: false } => "CTR_DRBG-AES-256",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|drbg| drbg.as_str() == name)
    }

    pub fn request<'a>(&self, entropy: &'a [u8], nonce: &'a [u8], personalization: &'a [u8], security_strength: usize, prediction_resistance: bool) -> RandomProviderRequest<'a> {
        RandomProviderRequest::new(self.as_str()).with_entropy(entropy).with_nonce(nonce).with_personalization(personalization).with_security_strength(security_strength).with_prediction_resistance(prediction_resistance)
    }

    pub fn instantiate(&self, entropy: &[u8], nonce: &[u8], personalization: &[u8], security_strength: usize, prediction_resistance: bool) -> Result<DRBGInstance, RandomError> {
        if security_strength > self.security_strength() {
            return Err(RandomError::Strength);
        }
        let security_strength = match Self::SECURITY_STRENGTHS.iter().copied().find(|strength| *strength >= security_strength) {
            Some(strength) => strength,
            None => return Err(RandomError::Strength),
        };
        if personalization.len() as u64 > self.maximum_input_size() {
            return Err(RandomError::Personalization);
        }
        if entropy.len() < self.minimum_entropy_size(security_strength) || entropy.len() as u64 > self.maximum_entropy_size() {
            return Err(RandomError::Entropy);
        }
        if self.nonce_required() == nonce.is_empty() {
            return Err(RandomError::Nonce);
        }
        match RandomProviders::open(&self.request(entropy, nonce, personalization, security_strength, prediction_resistance))? {
            Some(opening) => Ok(DRBGInstance { drbg: *self, security_strength, prediction_resistance, counter: 1, backend: opening.backend() }),
            None => todo!(),
        }
    }
}

impl fmt::Display for DRBG {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct DRBGInstance {
    drbg: DRBG,
    security_strength: usize,
    prediction_resistance: bool,
    counter: u64,
    backend: ProviderBackend<dyn RandomProvider>,
}

impl DRBGInstance {
    pub fn drbg(&self) -> DRBG {
        self.drbg
    }

    pub fn security_strength(&self) -> usize {
        self.security_strength
    }

    pub fn prediction_resistance(&self) -> bool {
        self.prediction_resistance
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }

    pub fn reseed_required(&self) -> bool {
        self.counter > self.drbg.reseed_interval()
    }

    pub fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<(), RandomError> {
        if entropy.len() < self.drbg.minimum_entropy_size(self.security_strength) || entropy.len() as u64 > self.drbg.maximum_entropy_size() {
            return Err(RandomError::Entropy);
        }
        if additional.len() as u64 > self.drbg.maximum_input_size() {
            return Err(RandomError::Additional);
        }
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.reseed(*handle, entropy, additional)?,
        }
        self.counter = 1;
        Ok(())
    }

    pub fn generate(&mut self, output: &mut [u8], additional: &[u8]) -> Result<(), RandomError> {
        if output.len() > self.drbg.maximum_request_size() {
            return Err(RandomError::Request);
        }
        if additional.len() as u64 > self.drbg.maximum_input_size() {
            return Err(RandomError::Additional);
        }
        if self.reseed_required() {
            return Err(RandomError::Reseed);
        }
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.generate(*handle, output, additional)?,
        }
        self.counter += 1;
        Ok(())
    }
}
