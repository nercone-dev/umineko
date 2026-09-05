use alloc::vec::Vec;
use crate::errors::PBKDF2Error;

use umineko_helpers::provider::{KDFProviderInputs, KDFProviderRequest, KDFProviders};

/// A keyed function that PBKDF2 calls once for every iteration of the derivation.
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
        let request = KDFProviderRequest::new("PBKDF2").with_prf(self.prf.name()?).with_iterations(self.iterations);
        Some(match self.prf.digest() {
            Some(digest) => request.with_digest(digest),
            None => request,
        })
    }

    pub fn derive(&self, password: &[u8], salt: &[u8], output: &mut [u8]) -> Result<(), PBKDF2Error> {
        if self.iterations == 0 {
            return Err(PBKDF2Error::Iterations);
        }
        match self.request().map(|request| KDFProviders::derive(&request, &KDFProviderInputs::new(password, salt), output)).transpose()?.flatten() {
            Some(()) => Ok(()),
            None => {
                self.stretch(password, salt, output);
                Ok(())
            }
        }
    }

    /// The blocks of the derivation, each one the exclusive or of every iteration of the function.
    pub fn stretch(&self, password: &[u8], salt: &[u8], output: &mut [u8]) {
        let size = self.prf.output_size();
        let mut current = alloc::vec![0; size];
        let mut next = alloc::vec![0; size];
        for (index, part) in output.chunks_mut(size).enumerate() {
            let mut message = Vec::with_capacity(salt.len() + 4);
            message.extend_from_slice(salt);
            message.extend_from_slice(&(index as u32 + 1).to_be_bytes());
            self.prf.compute(password, &message, &mut current);
            let mut block = current.clone();
            for _ in 1..self.iterations {
                self.prf.compute(password, &current, &mut next);
                for (total, value) in block.iter_mut().zip(&next) {
                    *total ^= value;
                }
                current.copy_from_slice(&next);
            }
            part.copy_from_slice(&block[..part.len()]);
        }
    }

    pub fn verify(&self, password: &[u8], salt: &[u8], expected: &[u8]) -> Result<(), PBKDF2Error> {
        let mut output = alloc::vec![0; expected.len()];
        self.derive(password, salt, &mut output)?;
        let mut difference = 0;
        for (left, right) in output.iter().zip(expected) {
            difference |= left ^ right;
        }
        match difference {
            0 => Ok(()),
            _ => Err(PBKDF2Error::Verification),
        }
    }
}
