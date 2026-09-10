use alloc::vec::Vec;
use crate::errors::TLSError;
use crate::types::TLSHash;

use umineko_helpers::provider::{KDFProviderInputs, KDFProviderRequest, KDFProviders};
use umineko_crypto_hmac::{HMAC, HMACHash};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TLSPRF {
    hash: TLSHash,
}

impl TLSPRF {
    pub const NAME: &'static str = "TLS-PRF";
    pub const MD5_SHA1_NAME: &'static str = "TLS-PRF-MD5-SHA1";

    pub fn new(hash: TLSHash) -> Self {
        Self { hash }
    }

    pub fn hash(&self) -> TLSHash {
        self.hash
    }

    pub fn request(&self) -> Option<KDFProviderRequest> {
        match (self.hash, self.hash.hmac()) {
            (TLSHash::MD5_SHA1, _) => Some(KDFProviderRequest::new(Self::MD5_SHA1_NAME)),
            (_, Some(hash)) => Some(KDFProviderRequest::new(Self::NAME).with_prf(hash.as_str())),
            (_, None) => None,
        }
    }

    pub fn expand(hash: HMACHash, secret: &[u8], seed: &[u8], output: &mut [u8]) {
        let size = hash.digest_size();
        let mut chain = seed.to_vec();
        let mut block = alloc::vec![0; size];
        let mut input = Vec::with_capacity(size + seed.len());
        for chunk in output.chunks_mut(size) {
            HMAC::tag(hash, secret, &chain, &mut block);
            chain.clear();
            chain.extend_from_slice(&block);
            input.clear();
            input.extend_from_slice(&chain);
            input.extend_from_slice(seed);
            HMAC::tag(hash, secret, &input, &mut block);
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }

    pub fn derive(&self, secret: &[u8], label: &[u8], seed: &[u8], output: &mut [u8]) -> Result<(), TLSError> {
        let request = self.request().ok_or(TLSError::Cipher)?;
        if KDFProviders::derive(&request, &KDFProviderInputs::new(secret, seed).with_info(label), output)?.is_some() {
            return Ok(());
        }
        let seed = [label, seed].concat();
        match (self.hash, self.hash.hmac()) {
            (TLSHash::MD5_SHA1, _) => {
                let half = secret.len().div_ceil(2);
                let mut other = alloc::vec![0; output.len()];
                Self::expand(HMACHash::MD5, &secret[..half], &seed, output);
                Self::expand(HMACHash::SHA1, &secret[secret.len() - half..], &seed, &mut other);
                for (byte, other) in output.iter_mut().zip(other) {
                    *byte ^= other;
                }
                Ok(())
            }
            (_, Some(hash)) => {
                Self::expand(hash, secret, &seed, output);
                Ok(())
            }
            (_, None) => Err(TLSError::Cipher),
        }
    }
}
