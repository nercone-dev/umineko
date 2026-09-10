use alloc::vec::Vec;
use core::fmt;
use crate::errors::DragonflyError;

use umineko_crypto_dh::DHGroup;
use umineko_crypto_ecdh::ECDHCurve;
use umineko_crypto_hmac::HMACHash;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DragonflyGroup {
    SECP256R1,
    SECP384R1,
    SECP521R1,
    BRAINPOOLP256R1,
    BRAINPOOLP384R1,
    BRAINPOOLP512R1,
    FFDHE2048,
    FFDHE3072,
    FFDHE4096,
    FFDHE6144,
    FFDHE8192,
}

impl DragonflyGroup {
    pub fn elliptic_curve(&self) -> bool {
        self.ecdh().is_some()
    }

    pub fn ecdh(&self) -> Option<ECDHCurve> {
        match self {
            Self::SECP256R1 => Some(ECDHCurve::SECP256R1),
            Self::SECP384R1 => Some(ECDHCurve::SECP384R1),
            Self::SECP521R1 => Some(ECDHCurve::SECP521R1),
            Self::BRAINPOOLP256R1 => Some(ECDHCurve::BRAINPOOLP256R1),
            Self::BRAINPOOLP384R1 => Some(ECDHCurve::BRAINPOOLP384R1),
            Self::BRAINPOOLP512R1 => Some(ECDHCurve::BRAINPOOLP512R1),
            Self::FFDHE2048 | Self::FFDHE3072 | Self::FFDHE4096 | Self::FFDHE6144 | Self::FFDHE8192 => None,
        }
    }

    pub fn dh(&self) -> Option<DHGroup> {
        match self {
            Self::FFDHE2048 => Some(DHGroup::FFDHE2048),
            Self::FFDHE3072 => Some(DHGroup::FFDHE3072),
            Self::FFDHE4096 => Some(DHGroup::FFDHE4096),
            Self::FFDHE6144 => Some(DHGroup::FFDHE6144),
            Self::FFDHE8192 => Some(DHGroup::FFDHE8192),
            Self::SECP256R1 | Self::SECP384R1 | Self::SECP521R1 | Self::BRAINPOOLP256R1 | Self::BRAINPOOLP384R1 | Self::BRAINPOOLP512R1 => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SECP256R1 => "secp256r1",
            Self::SECP384R1 => "secp384r1",
            Self::SECP521R1 => "secp521r1",
            Self::BRAINPOOLP256R1 => "brainpoolP256r1",
            Self::BRAINPOOLP384R1 => "brainpoolP384r1",
            Self::BRAINPOOLP512R1 => "brainpoolP512r1",
            Self::FFDHE2048 => "ffdhe2048",
            Self::FFDHE3072 => "ffdhe3072",
            Self::FFDHE4096 => "ffdhe4096",
            Self::FFDHE6144 => "ffdhe6144",
            Self::FFDHE8192 => "ffdhe8192",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "secp256r1" => Some(Self::SECP256R1),
            "secp384r1" => Some(Self::SECP384R1),
            "secp521r1" => Some(Self::SECP521R1),
            "brainpoolP256r1" => Some(Self::BRAINPOOLP256R1),
            "brainpoolP384r1" => Some(Self::BRAINPOOLP384R1),
            "brainpoolP512r1" => Some(Self::BRAINPOOLP512R1),
            "ffdhe2048" => Some(Self::FFDHE2048),
            "ffdhe3072" => Some(Self::FFDHE3072),
            "ffdhe4096" => Some(Self::FFDHE4096),
            "ffdhe6144" => Some(Self::FFDHE6144),
            "ffdhe8192" => Some(Self::FFDHE8192),
            _ => None,
        }
    }
}

impl fmt::Display for DragonflyGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dragonfly {
    pub group: DragonflyGroup,
    pub hash: HMACHash,
}

impl Dragonfly {
    pub fn new(group: DragonflyGroup, hash: HMACHash) -> Self {
        Self { group, hash }
    }

    pub fn element(&self, identity: &[u8], password: &[u8], salt: &[u8]) -> Result<DragonflyElement, DragonflyError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DragonflyElement {
    dragonfly: Dragonfly,
    element: Vec<u8>,
}

impl DragonflyElement {
    pub fn dragonfly(&self) -> Dragonfly {
        self.dragonfly
    }

    pub fn encode(&self) -> Vec<u8> {
        self.element.clone()
    }

    pub fn generate(&self, seed: &[u8]) -> Result<(DragonflyPrivateKey, DragonflyPublicKey), DragonflyError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DragonflyPrivateKey {
    element: DragonflyElement,
    private: Vec<u8>,
    mask: Vec<u8>,
}

impl DragonflyPrivateKey {
    pub fn password_element(&self) -> &DragonflyElement {
        &self.element
    }

    pub fn exchange(&self, peer: &DragonflyPublicKey) -> Result<DragonflySharedSecret, DragonflyError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DragonflyPublicKey {
    dragonfly: Dragonfly,
    scalar: Vec<u8>,
    element: Vec<u8>,
}

impl DragonflyPublicKey {
    pub fn decode(dragonfly: Dragonfly, data: &[u8]) -> Result<Self, DragonflyError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }

    pub fn dragonfly(&self) -> Dragonfly {
        self.dragonfly
    }

    pub fn scalar(&self) -> &[u8] {
        &self.scalar
    }

    pub fn element(&self) -> &[u8] {
        &self.element
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DragonflySharedSecret {
    secret: Vec<u8>,
}

impl DragonflySharedSecret {
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
