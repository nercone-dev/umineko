use crate::errors::RandomError;

use umineko_helpers::provider::{RandomProviderRequest, RandomProviders};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SystemRandom;

impl SystemRandom {
    pub const NAME: &'static str = "system";

    pub fn request() -> RandomProviderRequest<'static> {
        RandomProviderRequest::new(Self::NAME)
    }

    pub fn fill(output: &mut [u8]) -> Result<(), RandomError> {
        match RandomProviders::fill(&Self::request(), output)? {
            Some(()) => Ok(()),
            None => todo!(),
        }
    }
}
