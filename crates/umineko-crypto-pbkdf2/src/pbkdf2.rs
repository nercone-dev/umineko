use crate::errors::PBKDF2Error;

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
pub struct PBKDF2<P: PRF> {
    prf: P,
    iterations: u32,
}

impl<P: PRF> PBKDF2<P> {
    pub const RECOMMENDED_ITERATIONS: u32 = 600_000;

    pub fn new(prf: P, iterations: u32) -> Self {
        Self { prf, iterations }
    }

    pub fn prf(&self) -> &P {
        &self.prf
    }

    pub fn iterations(&self) -> u32 {
        self.iterations
    }

    pub fn request(&self) -> Option<KDFProviderRequest> {
        self.prf.name().map(|prf| KDFProviderRequest::new("PBKDF2").with_prf(prf).with_iterations(self.iterations))
    }

    pub fn derive(&self, password: &[u8], salt: &[u8], output: &mut [u8]) -> Result<(), PBKDF2Error> {
        if self.iterations == 0 {
            return Err(PBKDF2Error::Iterations);
        }
        match self.request().map(|request| KDFProviders::derive(&request, &KDFProviderInputs::new(password, salt), output)).transpose()?.flatten() {
            Some(()) => Ok(()),
            None => todo!(),
        }
    }

    pub fn verify(&self, password: &[u8], salt: &[u8], expected: &[u8]) -> Result<(), PBKDF2Error> {
        todo!()
    }
}
