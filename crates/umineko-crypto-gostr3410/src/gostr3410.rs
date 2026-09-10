use alloc::vec::Vec;
use core::fmt;
use crate::errors::GOSTR3410Error;

use umineko_helpers::provider::{ExchangeProviderRequest, ExchangeProviders, SignatureProviderRequest, SignatureProviders};
use umineko_hash_streebog::Streebog;
use umineko_crypto_hmac::HMACHash;
use umineko_crypto_kdftree::KDFTree;
use umineko_crypto_gost::{GOST28147, GOST28147Mode, GOST28147SBox};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GOSTR3410 {
    GC256A,
    GC256B,
    GC256C,
    GC256D,
    GC512A,
    GC512B,
    GC512C,
}

impl GOSTR3410 {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GC256A => "GC256A",
            Self::GC256B => "GC256B",
            Self::GC256C => "GC256C",
            Self::GC256D => "GC256D",
            Self::GC512A => "GC512A",
            Self::GC512B => "GC512B",
            Self::GC512C => "GC512C",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "GC256A" => Some(Self::GC256A),
            "GC256B" => Some(Self::GC256B),
            "GC256C" => Some(Self::GC256C),
            "GC256D" => Some(Self::GC256D),
            "GC512A" => Some(Self::GC512A),
            "GC512B" => Some(Self::GC512B),
            "GC512C" => Some(Self::GC512C),
            _ => None,
        }
    }

    pub fn parameter_set(&self) -> &'static str {
        match self {
            Self::GC256A => "id-tc26-gost-3410-2012-256-paramSetA",
            Self::GC256B => "id-GostR3410-2001-CryptoPro-A-ParamSet",
            Self::GC256C => "id-GostR3410-2001-CryptoPro-B-ParamSet",
            Self::GC256D => "id-GostR3410-2001-CryptoPro-C-ParamSet",
            Self::GC512A => "id-tc26-gost-3410-12-512-paramSetA",
            Self::GC512B => "id-tc26-gost-3410-12-512-paramSetB",
            Self::GC512C => "id-tc26-gost-3410-2012-512-paramSetC",
        }
    }

    pub fn exchange_name(&self, hash: Streebog) -> Option<&'static str> {
        match (self, hash) {
            (Self::GC256A, Streebog::V256) => Some("VKO-256-GC256A"),
            (Self::GC256B, Streebog::V256) => Some("VKO-256-GC256B"),
            (Self::GC256C, Streebog::V256) => Some("VKO-256-GC256C"),
            (Self::GC256D, Streebog::V256) => Some("VKO-256-GC256D"),
            (Self::GC512A, Streebog::V256) => Some("VKO-256-GC512A"),
            (Self::GC512B, Streebog::V256) => Some("VKO-256-GC512B"),
            (Self::GC512C, Streebog::V256) => Some("VKO-256-GC512C"),
            (Self::GC256A | Self::GC256B | Self::GC256C | Self::GC256D, Streebog::V512) => None,
            (Self::GC512A, Streebog::V512) => Some("VKO-512-GC512A"),
            (Self::GC512B, Streebog::V512) => Some("VKO-512-GC512B"),
            (Self::GC512C, Streebog::V512) => Some("VKO-512-GC512C"),
        }
    }

    pub fn coordinate_size(&self) -> usize {
        match self {
            Self::GC256A | Self::GC256B | Self::GC256C | Self::GC256D => 32,
            Self::GC512A | Self::GC512B | Self::GC512C => 64,
        }
    }

    pub fn public_key_size(&self) -> usize {
        self.coordinate_size() * 2
    }

    pub fn private_key_size(&self) -> usize {
        self.coordinate_size()
    }

    pub fn signature_size(&self) -> usize {
        self.coordinate_size() * 2
    }
}

impl fmt::Display for GOSTR3410 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl GOSTR3410 {
    pub fn request(&self) -> SignatureProviderRequest<'static> {
        SignatureProviderRequest::new(self.as_str())
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(GOSTR3410PrivateKey, GOSTR3410PublicKey), GOSTR3410Error> {
        match SignatureProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((GOSTR3410PrivateKey { variant: *self, key: private }, GOSTR3410PublicKey { variant: *self, key: public })),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GOSTR3410PrivateKey {
    variant: GOSTR3410,
    key: Vec<u8>,
}

impl GOSTR3410PrivateKey {
    pub const KEG_LABEL: &'static [u8] = b"kdf tree";

    pub fn decode(variant: GOSTR3410, data: &[u8]) -> Result<Self, GOSTR3410Error> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> GOSTR3410 {
        self.variant
    }

    pub fn public_key(&self) -> GOSTR3410PublicKey {
        let request = self.variant.request();
        match SignatureProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.public_key(&request, &self.key)) {
            Some(key) => GOSTR3410PublicKey { variant: self.variant, key },
            None => todo!(),
        }
    }

    pub fn sign(&self, digest: &[u8]) -> Result<GOSTR3410Signature, GOSTR3410Error> {
        match SignatureProviders::sign(&self.variant.request(), &self.key, digest)? {
            Some(signature) => Ok(GOSTR3410Signature { variant: self.variant, signature }),
            None => todo!(),
        }
    }

    pub fn exchange(&self, peer: &GOSTR3410PublicKey, ukm: &[u8], hash: Streebog) -> Result<GOSTR3410SharedSecret, GOSTR3410Error> {
        if peer.variant != self.variant {
            return Err(GOSTR3410Error::Curve);
        }
        let name = self.variant.exchange_name(hash).ok_or(GOSTR3410Error::Digest)?;
        match ExchangeProviders::exchange(&ExchangeProviderRequest::new(name).with_context(ukm), &self.key, &peer.key)? {
            Some(secret) => Ok(GOSTR3410SharedSecret { secret }),
            None => todo!(),
        }
    }

    pub fn keg(&self, peer: &GOSTR3410PublicKey, digest: &[u8; 32]) -> Result<GOSTR3410SharedSecret, GOSTR3410Error> {
        let mut ukm: Vec<u8> = digest[..16].iter().rev().copied().collect();
        if ukm.iter().all(|byte| *byte == 0) {
            ukm[0] = 1;
        }
        match self.variant {
            GOSTR3410::GC256A | GOSTR3410::GC256B | GOSTR3410::GC256C | GOSTR3410::GC256D => {
                let key = self.exchange(peer, &ukm, Streebog::V256)?;
                let mut secret = alloc::vec![0; 64];
                KDFTree::new(HMACHash::Streebog256, 1)?.derive(key.as_slice(), Self::KEG_LABEL, &digest[16..24], &mut secret)?;
                Ok(GOSTR3410SharedSecret { secret })
            }
            GOSTR3410::GC512A | GOSTR3410::GC512B | GOSTR3410::GC512C => self.exchange(peer, &ukm, Streebog::V512),
        }
    }

    pub fn keg_28147(&self, peer: &GOSTR3410PublicKey, digest: &[u8; 32], sbox: GOST28147SBox) -> Result<GOSTR3410SharedSecret, GOSTR3410Error> {
        let mut ukm = [0; GOST28147::UKM_SIZE];
        ukm.copy_from_slice(&digest[..GOST28147::UKM_SIZE]);
        let key = self.exchange(peer, &ukm, Streebog::V256)?;
        let key: &[u8; 32] = key.as_slice().try_into().map_err(|_| GOSTR3410Error::SharedSecret)?;
        let secret = GOST28147::new(GOST28147Mode::CFB, sbox, key).diversify(&ukm)?;
        Ok(GOSTR3410SharedSecret { secret: secret.to_vec() })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GOSTR3410PublicKey {
    variant: GOSTR3410,
    key: Vec<u8>,
}

impl GOSTR3410PublicKey {
    pub fn decode(variant: GOSTR3410, data: &[u8]) -> Result<Self, GOSTR3410Error> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> GOSTR3410 {
        self.variant
    }

    pub fn verify(&self, digest: &[u8], signature: &GOSTR3410Signature) -> Result<(), GOSTR3410Error> {
        match SignatureProviders::verify(&self.variant.request(), &self.key, digest, &signature.signature)? {
            Some(()) => Ok(()),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GOSTR3410Signature {
    variant: GOSTR3410,
    signature: Vec<u8>,
}

impl GOSTR3410Signature {
    pub fn decode(variant: GOSTR3410, data: &[u8]) -> Result<Self, GOSTR3410Error> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.signature.clone()
    }

    pub fn variant(&self) -> GOSTR3410 {
        self.variant
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GOSTR3410SharedSecret {
    secret: Vec<u8>,
}

impl GOSTR3410SharedSecret {
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
