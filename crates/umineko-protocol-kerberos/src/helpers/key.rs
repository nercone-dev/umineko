use alloc::vec::Vec;
use crate::errors::KerberosError;
use crate::types::{KerberosEncryptionType, KerberosChecksumType, KerberosKeyUsage};

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders, HashProviderRequest, HashProviders, KDFProviderInputs, KDFProviderRequest, KDFProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KerberosKeyDerivation {
    Checksum,
    Encryption,
    Integrity,
}

impl KerberosKeyDerivation {
    pub const ALL: [Self; 3] = [Self::Checksum, Self::Encryption, Self::Integrity];

    pub fn number(&self) -> u8 {
        match self {
            Self::Checksum => 0x99,
            Self::Encryption => 0xAA,
            Self::Integrity => 0x55,
        }
    }

    pub fn constant(&self, usage: KerberosKeyUsage) -> [u8; 5] {
        let mut constant = [0; 5];
        constant[..4].copy_from_slice(&usage.0.to_be_bytes());
        constant[4] = self.number();
        constant
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Checksum => "Kc",
            Self::Encryption => "Ke",
            Self::Integrity => "Ki",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KerberosKey {
    encryption: KerberosEncryptionType,
    value: Vec<u8>,
}

impl KerberosKey {
    pub const PRF_CONSTANT: &'static [u8] = b"prf";
    pub const STRING_TO_KEY_CONSTANT: &'static [u8] = b"kerberos";

    pub fn new(encryption: KerberosEncryptionType, value: &[u8]) -> Result<Self, KerberosError> {
        match encryption.key_size() {
            Some(size) if size == value.len() => Ok(Self { encryption, value: value.to_vec() }),
            Some(_) => Err(KerberosError::Key),
            None => Err(KerberosError::EncryptionType),
        }
    }

    pub fn string_to_key(encryption: KerberosEncryptionType, password: &[u8], salt: &[u8], parameters: Option<&[u8]>) -> Result<Self, KerberosError> {
        let size = encryption.key_size().ok_or(KerberosError::EncryptionType)?;
        let parameters = parameters.or(encryption.parameters()).ok_or(KerberosError::EncryptionType)?;
        let mut value = alloc::vec![0; size];
        match KDFProviders::derive(&KDFProviderRequest::new(encryption.as_str()), &KDFProviderInputs::new(password, salt).with_info(parameters), &mut value)? {
            Some(()) => Ok(Self { encryption, value }),
            None => todo!(),
        }
    }

    pub fn random_to_key(encryption: KerberosEncryptionType, seed: &[u8]) -> Result<Self, KerberosError> {
        todo!()
    }

    pub fn encryption(&self) -> KerberosEncryptionType {
        self.encryption
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.value
    }

    pub fn random(&self, constant: &[u8]) -> Result<Vec<u8>, KerberosError> {
        todo!()
    }

    pub fn derive(&self, constant: &[u8]) -> Result<Self, KerberosError> {
        todo!()
    }

    pub fn derive_usage(&self, usage: KerberosKeyUsage, derivation: KerberosKeyDerivation) -> Result<Self, KerberosError> {
        self.derive(&derivation.constant(usage))
    }

    pub fn prf(&self, data: &[u8]) -> Result<Vec<u8>, KerberosError> {
        todo!()
    }

    pub fn request(&self, usage: KerberosKeyUsage) -> CipherProviderRequest<'_> {
        CipherProviderRequest::new(self.encryption.as_str(), &self.value).with_counter(usage.0)
    }

    pub fn encrypt(&self, usage: KerberosKeyUsage, plaintext: &[u8]) -> Result<Vec<u8>, KerberosError> {
        match CipherProviders::encrypt(&self.request(usage), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => todo!(),
        }
    }

    pub fn decrypt(&self, usage: KerberosKeyUsage, ciphertext: &[u8]) -> Result<Vec<u8>, KerberosError> {
        match CipherProviders::decrypt(&self.request(usage), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => todo!(),
        }
    }

    pub fn checksum(&self, checksum: KerberosChecksumType, usage: KerberosKeyUsage, data: &[u8]) -> Result<Vec<u8>, KerberosError> {
        let mut output = alloc::vec![0; checksum.size()];
        match HashProviders::try_digest(&HashProviderRequest::new(checksum.as_str()).with_key(&self.value).with_seed(usage.0 as u64), data, &mut output)? {
            Some(length) => {
                output.truncate(length);
                Ok(output)
            }
            None => todo!(),
        }
    }

    pub fn verify(&self, checksum: KerberosChecksumType, usage: KerberosKeyUsage, data: &[u8], expected: &[u8]) -> Result<(), KerberosError> {
        if checksum.confounded() {
            todo!()
        }
        let computed = self.checksum(checksum, usage, data)?;
        if computed.len() != expected.len() {
            return Err(KerberosError::Integrity);
        }
        let mut difference = 0;
        for (left, right) in computed.iter().zip(expected) {
            difference |= left ^ right;
        }
        match difference {
            0 => Ok(()),
            _ => Err(KerberosError::Integrity),
        }
    }
}
