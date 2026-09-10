use alloc::vec::Vec;
use core::fmt;
use crate::errors::DHError;

use umineko_helpers::provider::{ExchangeProviderRequest, ExchangeProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DHGroup {
    FFDHE2048,
    FFDHE3072,
    FFDHE4096,
    FFDHE6144,
    FFDHE8192,
    MODP768,
    MODP1024,
    MODP1536,
    MODP2048,
    MODP3072,
    MODP4096,
    MODP6144,
    MODP8192,
}

impl DHGroup {
    pub fn bits(&self) -> usize {
        match self {
            Self::FFDHE2048 => 2048,
            Self::FFDHE3072 => 3072,
            Self::FFDHE4096 => 4096,
            Self::FFDHE6144 => 6144,
            Self::FFDHE8192 => 8192,
            Self::MODP768 => 768,
            Self::MODP1024 => 1024,
            Self::MODP1536 => 1536,
            Self::MODP2048 => 2048,
            Self::MODP3072 => 3072,
            Self::MODP4096 => 4096,
            Self::MODP6144 => 6144,
            Self::MODP8192 => 8192,
        }
    }

    pub fn parameters(&self) -> DHParameters {
        todo!()
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FFDHE2048 => "ffdhe2048",
            Self::FFDHE3072 => "ffdhe3072",
            Self::FFDHE4096 => "ffdhe4096",
            Self::FFDHE6144 => "ffdhe6144",
            Self::FFDHE8192 => "ffdhe8192",
            Self::MODP768 => "modp768",
            Self::MODP1024 => "modp1024",
            Self::MODP1536 => "modp1536",
            Self::MODP2048 => "modp2048",
            Self::MODP3072 => "modp3072",
            Self::MODP4096 => "modp4096",
            Self::MODP6144 => "modp6144",
            Self::MODP8192 => "modp8192",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ffdhe2048" => Some(Self::FFDHE2048),
            "ffdhe3072" => Some(Self::FFDHE3072),
            "ffdhe4096" => Some(Self::FFDHE4096),
            "ffdhe6144" => Some(Self::FFDHE6144),
            "ffdhe8192" => Some(Self::FFDHE8192),
            "modp768" => Some(Self::MODP768),
            "modp1024" => Some(Self::MODP1024),
            "modp1536" => Some(Self::MODP1536),
            "modp2048" => Some(Self::MODP2048),
            "modp3072" => Some(Self::MODP3072),
            "modp4096" => Some(Self::MODP4096),
            "modp6144" => Some(Self::MODP6144),
            "modp8192" => Some(Self::MODP8192),
            _ => None,
        }
    }
}

impl fmt::Display for DHGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DHParameters {
    prime: Vec<u8>,
    generator: Vec<u8>,
    order: Option<Vec<u8>>,
    encoded: Vec<u8>,
}

impl DHParameters {
    pub fn new(prime: &[u8], generator: &[u8], order: Option<&[u8]>) -> Result<Self, DHError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<Self, DHError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.encoded.clone()
    }

    pub fn prime(&self) -> &[u8] {
        &self.prime
    }

    pub fn generator(&self) -> &[u8] {
        &self.generator
    }

    pub fn order(&self) -> Option<&[u8]> {
        self.order.as_deref()
    }

    pub fn bits(&self) -> usize {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DH {
    Group(DHGroup),
    Parameters(DHParameters),
}

impl DH {
    pub const NAME: &'static str = "DH";

    pub fn bits(&self) -> usize {
        match self {
            Self::Group(group) => group.bits(),
            Self::Parameters(parameters) => parameters.bits(),
        }
    }

    pub fn request(&self) -> ExchangeProviderRequest<'_> {
        match self {
            Self::Group(group) => ExchangeProviderRequest::new(group.as_str()),
            Self::Parameters(parameters) => ExchangeProviderRequest::new(Self::NAME).with_parameters(&parameters.encoded),
        }
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(DHPrivateKey, DHPublicKey), DHError> {
        match ExchangeProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((DHPrivateKey { domain: self.clone(), key: private }, DHPublicKey { domain: self.clone(), key: public })),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DHPrivateKey {
    domain: DH,
    key: Vec<u8>,
}

impl DHPrivateKey {
    pub fn decode(domain: DH, data: &[u8]) -> Result<Self, DHError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn domain(&self) -> &DH {
        &self.domain
    }

    pub fn public_key(&self) -> DHPublicKey {
        let request = self.domain.request();
        match ExchangeProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.public_key(&request, &self.key)) {
            Some(key) => DHPublicKey { domain: self.domain.clone(), key },
            None => todo!(),
        }
    }

    pub fn exchange(&self, peer: &DHPublicKey) -> Result<DHSharedSecret, DHError> {
        match ExchangeProviders::exchange(&self.domain.request(), &self.key, &peer.key)? {
            Some(secret) => Ok(DHSharedSecret { secret }),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DHPublicKey {
    domain: DH,
    key: Vec<u8>,
}

impl DHPublicKey {
    pub fn decode(domain: DH, data: &[u8]) -> Result<Self, DHError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn domain(&self) -> &DH {
        &self.domain
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DHSharedSecret {
    secret: Vec<u8>,
}

impl DHSharedSecret {
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
