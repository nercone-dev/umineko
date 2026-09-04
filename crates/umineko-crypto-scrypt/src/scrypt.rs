use crate::errors::ScryptError;

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
pub struct Scrypt<P: PRF> {
    prf: P,
    cost: u32,
    block: u32,
    parallelism: u32,
}

impl<P: PRF> Scrypt<P> {
    pub const RECOMMENDED_COST: u32 = 1 << 17;
    pub const RECOMMENDED_BLOCK: u32 = 8;
    pub const RECOMMENDED_PARALLELISM: u32 = 1;

    pub fn new(prf: P, cost: u32, block: u32, parallelism: u32) -> Result<Self, ScryptError> {
        todo!()
    }

    pub fn prf(&self) -> &P {
        &self.prf
    }

    pub fn memory(&self) -> usize {
        todo!()
    }

    pub fn request(&self) -> Option<KDFProviderRequest> {
        self.prf.name().map(|prf| KDFProviderRequest::new("scrypt").with_prf(prf).with_cost(self.cost, self.block, self.parallelism))
    }

    pub fn derive(&self, password: &[u8], salt: &[u8], output: &mut [u8]) -> Result<(), ScryptError> {
        match self.request().map(|request| KDFProviders::derive(&request, &KDFProviderInputs::new(password, salt), output)).transpose()?.flatten() {
            Some(()) => Ok(()),
            None => todo!(),
        }
    }

    pub fn verify(&self, password: &[u8], salt: &[u8], expected: &[u8]) -> Result<(), ScryptError> {
        todo!()
    }
}
