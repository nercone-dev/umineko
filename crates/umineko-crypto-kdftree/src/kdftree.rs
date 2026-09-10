use alloc::vec::Vec;
use crate::errors::KDFTreeError;

use umineko_helpers::provider::{KDFProviderInputs, KDFProviderRequest, KDFProviders};
use umineko_crypto_hmac::{HMAC, HMACHash};

///
pub trait PRF {
    fn output_size(&self) -> usize;

    fn compute(&self, key: &[u8], data: &[u8], output: &mut [u8]);

    fn name(&self) -> Option<&'static str> {
        None
    }
}

impl PRF for HMACHash {
    fn output_size(&self) -> usize {
        self.digest_size()
    }

    fn compute(&self, key: &[u8], data: &[u8], output: &mut [u8]) {
        HMAC::tag(*self, key, data, output);
    }

    fn name(&self) -> Option<&'static str> {
        Some(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KDFTree<P: PRF> {
    prf: P,
    counter_size: usize,
}

impl<P: PRF> KDFTree<P> {
    pub const NAME: &'static str = "KDF_TREE";
    pub const SEPARATOR: u8 = 0x00;
    pub const MINIMUM_COUNTER_SIZE: usize = 1;
    pub const MAXIMUM_COUNTER_SIZE: usize = 4;

    pub fn new(prf: P, counter_size: usize) -> Result<Self, KDFTreeError> {
        if !(Self::MINIMUM_COUNTER_SIZE..=Self::MAXIMUM_COUNTER_SIZE).contains(&counter_size) {
            return Err(KDFTreeError::Counter);
        }
        Ok(Self { prf, counter_size })
    }

    pub fn prf(&self) -> &P {
        &self.prf
    }

    pub fn counter_size(&self) -> usize {
        self.counter_size
    }

    pub fn maximum_blocks(&self) -> u64 {
        (1u64 << (8 * self.counter_size)) - 1
    }

    pub fn request(&self) -> Option<KDFProviderRequest> {
        self.prf.name().map(|prf| KDFProviderRequest::new(Self::NAME).with_prf(prf).with_counter_size(self.counter_size as u32))
    }

    pub fn input(&self, index: u32, label: &[u8], seed: &[u8], length: usize) -> Result<Vec<u8>, KDFTreeError> {
        if index == 0 || index as u64 > self.maximum_blocks() {
            return Err(KDFTreeError::Counter);
        }
        if length == 0 {
            return Err(KDFTreeError::Length);
        }
        let counter = index.to_be_bytes();
        let bits = (length as u128 * 8).to_be_bytes();
        let skip = bits.iter().take_while(|byte| **byte == 0).count();
        let mut input = Vec::with_capacity(self.counter_size + label.len() + 1 + seed.len() + bits.len() - skip);
        input.extend_from_slice(&counter[counter.len() - self.counter_size..]);
        input.extend_from_slice(label);
        input.push(Self::SEPARATOR);
        input.extend_from_slice(seed);
        input.extend_from_slice(&bits[skip..]);
        Ok(input)
    }

    pub fn derive(&self, key: &[u8], label: &[u8], seed: &[u8], output: &mut [u8]) -> Result<(), KDFTreeError> {
        let size = self.prf.output_size();
        if output.is_empty() || size == 0 || output.len().div_ceil(size) as u64 > self.maximum_blocks() {
            return Err(KDFTreeError::Length);
        }
        match self.request().map(|request| KDFProviders::derive(&request, &KDFProviderInputs::new(key, seed).with_info(label), output)).transpose()?.flatten() {
            Some(()) => Ok(()),
            None => {
                let length = output.len();
                let mut block = alloc::vec![0; size];
                for (index, chunk) in output.chunks_mut(size).enumerate() {
                    self.prf.compute(key, &self.input(index as u32 + 1, label, seed, length)?, &mut block);
                    chunk.copy_from_slice(&block[..chunk.len()]);
                }
                Ok(())
            }
        }
    }
}
