use umineko_provider::{CipherProvider, CipherProviderRequest, SignatureProvider, SignatureProviderRequest, ExchangeProvider, ExchangeProviderRequest, KDFProvider, KDFProviderRequest, KDFProviderInputs, ProviderError};
use alloc::vec::Vec;
use crate::netbsd::NetBSDProvider;

impl CipherProvider for NetBSDProvider {
    fn supports(&self, request: &CipherProviderRequest<'_>) -> bool {
        let _ = request;
        false
    }

    fn encrypt(&self, request: &CipherProviderRequest<'_>, plaintext: &[u8]) -> Result<Vec<u8>, ProviderError> {
        todo!()
    }

    fn decrypt(&self, request: &CipherProviderRequest<'_>, ciphertext: &[u8]) -> Result<Vec<u8>, ProviderError> {
        todo!()
    }
}

impl SignatureProvider for NetBSDProvider {
    fn supports(&self, request: &SignatureProviderRequest<'_>) -> bool {
        let _ = request;
        false
    }

    fn generate(&self, request: &SignatureProviderRequest<'_>) -> Result<(Vec<u8>, Vec<u8>), ProviderError> {
        todo!()
    }

    fn public_key(&self, request: &SignatureProviderRequest<'_>, private: &[u8]) -> Result<Vec<u8>, ProviderError> {
        todo!()
    }

    fn sign(&self, request: &SignatureProviderRequest<'_>, private: &[u8], message: &[u8]) -> Result<Vec<u8>, ProviderError> {
        todo!()
    }

    fn verify(&self, request: &SignatureProviderRequest<'_>, public: &[u8], message: &[u8], signature: &[u8]) -> Result<(), ProviderError> {
        todo!()
    }
}

impl ExchangeProvider for NetBSDProvider {
    fn supports(&self, request: &ExchangeProviderRequest<'_>) -> bool {
        let _ = request;
        false
    }

    fn generate(&self, request: &ExchangeProviderRequest<'_>) -> Result<(Vec<u8>, Vec<u8>), ProviderError> {
        todo!()
    }

    fn public_key(&self, request: &ExchangeProviderRequest<'_>, private: &[u8]) -> Result<Vec<u8>, ProviderError> {
        todo!()
    }
}

impl KDFProvider for NetBSDProvider {
    fn supports(&self, request: &KDFProviderRequest) -> bool {
        let _ = request;
        false
    }

    fn derive(&self, request: &KDFProviderRequest, inputs: &KDFProviderInputs<'_>, output: &mut [u8]) -> Result<(), ProviderError> {
        todo!()
    }
}
