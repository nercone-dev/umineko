use alloc::vec::Vec;
use crate::errors::HKDFError;

use umineko_helpers::provider::{KDFProviderInputs, KDFProviderRequest, KDFProviders};

/// A keyed function that HKDF calls to extract one key and to expand it.
pub trait PRF {
    fn output_size(&self) -> usize;

    fn compute(&self, key: &[u8], data: &[u8], output: &mut [u8]);

    fn name(&self) -> Option<&'static str> {
        None
    }

    fn digest(&self) -> Option<&'static str> {
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HKDF<P: PRF> {
    prf: P,
}

impl<P: PRF> HKDF<P> {
    pub const MAXIMUM_BLOCKS: usize = 255;

    pub fn new(prf: P) -> Self {
        Self { prf }
    }

    pub fn prf(&self) -> &P {
        &self.prf
    }

    pub fn request(&self, algorithm: &'static str) -> Option<KDFProviderRequest> {
        let request = KDFProviderRequest::new(algorithm).with_prf(self.prf.name()?);
        Some(match self.prf.digest() {
            Some(digest) => request.with_digest(digest),
            None => request,
        })
    }

    pub fn extract(&self, salt: &[u8], material: &[u8]) -> Vec<u8> {
        let mut output = alloc::vec![0; self.prf.output_size()];
        let request = self.request("HKDF-Extract");
        match request.and_then(|request| KDFProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.derive(&request, &KDFProviderInputs::new(material, salt), &mut output))) {
            Some(()) => output,
            None => {
                self.prf.compute(salt, material, &mut output);
                output
            }
        }
    }

    pub fn expand(&self, key: &[u8], info: &[u8], output: &mut [u8]) -> Result<(), HKDFError> {
        if output.len() > Self::MAXIMUM_BLOCKS * self.prf.output_size() {
            return Err(HKDFError::Length);
        }
        match self.request("HKDF-Expand").map(|request| KDFProviders::derive(&request, &KDFProviderInputs::new(key, &[]).with_info(info), output)).transpose()?.flatten() {
            Some(()) => Ok(()),
            None => {
                self.stretch(key, info, output);
                Ok(())
            }
        }
    }

    pub fn derive(&self, salt: &[u8], material: &[u8], info: &[u8], output: &mut [u8]) -> Result<(), HKDFError> {
        if output.len() > Self::MAXIMUM_BLOCKS * self.prf.output_size() {
            return Err(HKDFError::Length);
        }
        match self.request("HKDF").map(|request| KDFProviders::derive(&request, &KDFProviderInputs::new(material, salt).with_info(info), output)).transpose()?.flatten() {
            Some(()) => Ok(()),
            None => {
                self.stretch(&self.extract(salt, material), info, output);
                Ok(())
            }
        }
    }

    /// The blocks of the expansion, each one over the block before it, the context and its own index.
    pub fn stretch(&self, key: &[u8], info: &[u8], output: &mut [u8]) {
        let size = self.prf.output_size();
        let mut previous = Vec::new();
        let mut block = alloc::vec![0; size];
        for (index, part) in output.chunks_mut(size).enumerate() {
            let mut message = Vec::with_capacity(previous.len() + info.len() + 1);
            message.extend_from_slice(&previous);
            message.extend_from_slice(info);
            message.push(index as u8 + 1);
            self.prf.compute(key, &message, &mut block);
            part.copy_from_slice(&block[..part.len()]);
            previous = block.clone();
        }
    }
}
