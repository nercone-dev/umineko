use alloc::vec::Vec;
use core::fmt;
use crate::errors::IBSError;

use umineko_helpers::provider::{SignatureProviderRequest, SignatureProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IBS {
    IBS1,
    IBS2,
    ChineseIBS,
}

impl IBS {
    pub const ALL: [Self; 3] = [Self::IBS1, Self::IBS2, Self::ChineseIBS];

    pub fn object_identifier(&self) -> &'static str {
        match self {
            Self::IBS1 => "1.0.14888.3.0.7",
            Self::IBS2 => "1.0.14888.3.0.8",
            Self::ChineseIBS => "1.2.156.10197.1.302.1",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::IBS1 => "IBS-1",
            Self::IBS2 => "IBS-2",
            Self::ChineseIBS => "Chinese-IBS",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|variant| variant.as_str() == name)
    }

    pub fn from_object_identifier(identifier: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|variant| variant.object_identifier() == identifier)
    }

    pub fn request(&self) -> SignatureProviderRequest<'static> {
        SignatureProviderRequest::new(self.as_str())
    }

    pub fn setup(&self, seed: &[u8]) -> Result<(IBSMasterKey, IBSPublicParameters), IBSError> {
        match SignatureProviders::generate(&self.request().with_seed(seed))? {
            Some((private, public)) => Ok((IBSMasterKey { variant: *self, key: private }, IBSPublicParameters { variant: *self, parameters: public })),
            None => todo!(),
        }
    }
}

impl fmt::Display for IBS {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IBSMasterKey {
    variant: IBS,
    key: Vec<u8>,
}

impl IBSMasterKey {
    pub fn decode(variant: IBS, data: &[u8]) -> Result<Self, IBSError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn variant(&self) -> IBS {
        self.variant
    }

    pub fn public_parameters(&self) -> Result<IBSPublicParameters, IBSError> {
        match SignatureProviders::public_key(&self.variant.request(), &self.key)? {
            Some(parameters) => Ok(IBSPublicParameters { variant: self.variant, parameters }),
            None => todo!(),
        }
    }

    pub fn extract(&self, identity: &[u8]) -> Result<IBSSigningKey, IBSError> {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IBSPublicParameters {
    variant: IBS,
    parameters: Vec<u8>,
}

impl IBSPublicParameters {
    pub fn decode(variant: IBS, data: &[u8]) -> Result<Self, IBSError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.parameters.clone()
    }

    pub fn variant(&self) -> IBS {
        self.variant
    }

    pub fn verify(&self, identity: &[u8], message: &[u8], signature: &IBSSignature) -> Result<(), IBSError> {
        if signature.variant != self.variant {
            return Err(IBSError::Variant);
        }
        match SignatureProviders::verify(&self.variant.request().with_context(identity), &self.parameters, message, &signature.signature)? {
            Some(()) => Ok(()),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IBSSigningKey {
    variant: IBS,
    identity: Vec<u8>,
    key: Vec<u8>,
}

impl IBSSigningKey {
    pub fn decode(variant: IBS, identity: &[u8], data: &[u8]) -> Result<Self, IBSError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.key.clone()
    }

    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    pub fn variant(&self) -> IBS {
        self.variant
    }

    pub fn sign(&self, message: &[u8], seed: &[u8]) -> Result<IBSSignature, IBSError> {
        match SignatureProviders::sign(&self.variant.request().with_context(&self.identity).with_seed(seed), &self.key, message)? {
            Some(signature) => Ok(IBSSignature { variant: self.variant, signature }),
            None => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IBSSignature {
    variant: IBS,
    signature: Vec<u8>,
}

impl IBSSignature {
    pub fn decode(variant: IBS, data: &[u8]) -> Result<Self, IBSError> {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        self.signature.clone()
    }

    pub fn variant(&self) -> IBS {
        self.variant
    }
}
