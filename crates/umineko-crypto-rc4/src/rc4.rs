use alloc::vec::Vec;
use crate::errors::RC4Error;

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RC4 {
    key: Vec<u8>,
    state: [u8; 256],
    i: u8,
    j: u8,
    position: u32,
}

impl RC4 {
    pub const NAME: &'static str = "RC4";
    pub const MINIMUM_KEY_SIZE: usize = 1;
    pub const MAXIMUM_KEY_SIZE: usize = 256;

    pub fn new(key: &[u8]) -> Result<Self, RC4Error> {
        if key.len() < Self::MINIMUM_KEY_SIZE || key.len() > Self::MAXIMUM_KEY_SIZE {
            return Err(RC4Error::Key);
        }
        Ok(Self { key: key.to_vec(), state: [0; 256], i: 0, j: 0, position: 0 })
    }

    pub fn position(&self) -> u32 {
        self.position
    }

    pub fn request(&self) -> CipherProviderRequest<'_> {
        CipherProviderRequest::new(Self::NAME, &self.key).with_counter(self.position)
    }

    pub fn apply(&mut self, data: &[u8]) -> Vec<u8> {
        let request = self.request();
        match CipherProviders::global().select(|provider| provider.supports(&request)).require(|provider| provider.encrypt(&request, data)) {
            Some(output) => {
                self.position = self.position.wrapping_add(data.len() as u32);
                output
            }
            None => todo!(),
        }
    }
}
