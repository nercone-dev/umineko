use alloc::vec::Vec;
use crate::errors::HKDFError;

use umineko_helpers::provider::{KDFProviderInputs, KDFProviderRequest, KDFProviders};

///
pub trait PRF {
    fn output_size(&self) -> usize;

    fn compute(&self, key: &[u8], data: &[u8], output: &mut [u8]);

    fn name(&self) -> Option<&'static str> {
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
        self.prf.name().map(|prf| KDFProviderRequest::new(algorithm).with_prf(prf))
    }

    pub fn extract(&self, salt: &[u8], material: &[u8]) -> Vec<u8> {
        let mut output = alloc::vec![0; self.prf.output_size()];
        let request = self.request("HKDF-Extract");
        match request.and_then(|request| KDFProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.derive(&request, &KDFProviderInputs::new(material, salt), &mut output))) {
            Some(()) => output,
            None => todo!(),
        }
    }

    pub fn expand(&self, key: &[u8], info: &[u8], output: &mut [u8]) -> Result<(), HKDFError> {
        if output.len() > Self::MAXIMUM_BLOCKS * self.prf.output_size() {
            return Err(HKDFError::Length);
        }
        match self.request("HKDF-Expand").map(|request| KDFProviders::derive(&request, &KDFProviderInputs::new(key, &[]).with_info(info), output)).transpose()?.flatten() {
            Some(()) => Ok(()),
            None => todo!(),
        }
    }

    pub fn derive(&self, salt: &[u8], material: &[u8], info: &[u8], output: &mut [u8]) -> Result<(), HKDFError> {
        if output.len() > Self::MAXIMUM_BLOCKS * self.prf.output_size() {
            return Err(HKDFError::Length);
        }
        match self.request("HKDF").map(|request| KDFProviders::derive(&request, &KDFProviderInputs::new(material, salt).with_info(info), output)).transpose()?.flatten() {
            Some(()) => Ok(()),
            None => todo!(),
        }
    }
}
