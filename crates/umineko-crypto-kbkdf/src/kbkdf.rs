use alloc::vec::Vec;
use core::fmt;
use crate::errors::KBKDFError;

use umineko_helpers::provider::{KDFProviderInputs, KDFProviderRequest, KDFProviders};
use umineko_crypto_hmac::{HMAC, HMACHash};
use umineko_crypto_cmac::{CMAC, CMACCipher};

///
pub trait PRF {
    fn output_size(&self) -> usize;

    fn key_size(&self) -> Option<usize> {
        None
    }

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

impl PRF for CMACCipher {
    fn output_size(&self) -> usize {
        self.tag_size()
    }

    fn key_size(&self) -> Option<usize> {
        Some(CMACCipher::key_size(self))
    }

    /// Panics when the key size differs from the cipher key size.
    fn compute(&self, key: &[u8], data: &[u8], output: &mut [u8]) {
        CMAC::tag(*self, key, data, output).expect("the key size matches the cipher");
    }

    fn name(&self) -> Option<&'static str> {
        Some(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KBKDFMode {
    Counter,
    Feedback,
    DoublePipeline,
}

impl KBKDFMode {
    pub const ALL: [Self; 3] = [Self::Counter, Self::Feedback, Self::DoublePipeline];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Counter => "KBKDF-Counter",
            Self::Feedback => "KBKDF-Feedback",
            Self::DoublePipeline => "KBKDF-Double-Pipeline",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|mode| mode.as_str() == name)
    }
}

impl fmt::Display for KBKDFMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KBKDF<P: PRF> {
    prf: P,
    mode: KBKDFMode,
    counter_size: Option<usize>,
    length_size: usize,
}

impl<P: PRF> KBKDF<P> {
    pub const SEPARATOR: u8 = 0x00;
    pub const MINIMUM_COUNTER_SIZE: usize = 1;
    pub const MAXIMUM_COUNTER_SIZE: usize = 4;
    pub const MINIMUM_LENGTH_SIZE: usize = 1;
    pub const MAXIMUM_LENGTH_SIZE: usize = 8;

    pub fn new(prf: P, mode: KBKDFMode, counter_size: Option<usize>, length_size: usize) -> Result<Self, KBKDFError> {
        match counter_size {
            None if mode == KBKDFMode::Counter => return Err(KBKDFError::Counter),
            Some(size) if !(Self::MINIMUM_COUNTER_SIZE..=Self::MAXIMUM_COUNTER_SIZE).contains(&size) => return Err(KBKDFError::Counter),
            _ => {}
        }
        if !(Self::MINIMUM_LENGTH_SIZE..=Self::MAXIMUM_LENGTH_SIZE).contains(&length_size) {
            return Err(KBKDFError::Length);
        }
        Ok(Self { prf, mode, counter_size, length_size })
    }

    pub fn prf(&self) -> &P {
        &self.prf
    }

    pub fn mode(&self) -> KBKDFMode {
        self.mode
    }

    pub fn counter_size(&self) -> Option<usize> {
        self.counter_size
    }

    pub fn length_size(&self) -> usize {
        self.length_size
    }

    pub fn maximum_blocks(&self) -> u64 {
        match self.counter_size {
            Some(size) => (1u64 << (8 * size)) - 1,
            None => u64::from(u32::MAX),
        }
    }

    pub fn request(&self) -> Option<KDFProviderRequest> {
        self.prf.name().map(|prf| KDFProviderRequest::new(self.mode.as_str()).with_prf(prf).with_counter_size(self.counter_size.unwrap_or(0) as u32).with_length_size(self.length_size as u32))
    }

    pub fn fixed(&self, label: &[u8], context: &[u8], length: usize) -> Result<Vec<u8>, KBKDFError> {
        let bits = (length as u128 * 8).to_be_bytes();
        let skip = bits.len() - self.length_size;
        if length == 0 || bits[..skip].iter().any(|byte| *byte != 0) {
            return Err(KBKDFError::Length);
        }
        let mut fixed = Vec::with_capacity(label.len() + 1 + context.len() + self.length_size);
        fixed.extend_from_slice(label);
        fixed.push(Self::SEPARATOR);
        fixed.extend_from_slice(context);
        fixed.extend_from_slice(&bits[skip..]);
        Ok(fixed)
    }

    pub fn input(&self, index: u32, chain: &[u8], fixed: &[u8]) -> Result<Vec<u8>, KBKDFError> {
        if index == 0 || u64::from(index) > self.maximum_blocks() {
            return Err(KBKDFError::Counter);
        }
        let counter = index.to_be_bytes();
        let size = self.counter_size.unwrap_or(0);
        let mut input = Vec::with_capacity(chain.len() + size + fixed.len());
        input.extend_from_slice(chain);
        input.extend_from_slice(&counter[counter.len() - size..]);
        input.extend_from_slice(fixed);
        Ok(input)
    }

    pub fn derive(&self, key: &[u8], label: &[u8], context: &[u8], iv: &[u8], output: &mut [u8]) -> Result<(), KBKDFError> {
        if self.prf.key_size().is_some_and(|size| size != key.len()) {
            return Err(KBKDFError::Key);
        }
        if self.mode != KBKDFMode::Feedback && !iv.is_empty() {
            return Err(KBKDFError::IV);
        }
        let size = self.prf.output_size();
        if output.is_empty() || size == 0 || output.len().div_ceil(size) as u64 > self.maximum_blocks() {
            return Err(KBKDFError::Length);
        }
        let fixed = self.fixed(label, context, output.len())?;
        match self.request().map(|request| KDFProviders::derive(&request, &KDFProviderInputs::new(key, iv).with_info(label).with_associated(context), output)).transpose()?.flatten() {
            Some(()) => Ok(()),
            None => {
                let mut chain = match self.mode {
                    KBKDFMode::Counter => Vec::new(),
                    KBKDFMode::Feedback => iv.to_vec(),
                    KBKDFMode::DoublePipeline => fixed.clone(),
                };
                let mut block = alloc::vec![0; size];
                for (index, chunk) in output.chunks_mut(size).enumerate() {
                    if self.mode == KBKDFMode::DoublePipeline {
                        self.prf.compute(key, &chain, &mut block);
                        chain.clone_from(&block);
                    }
                    self.prf.compute(key, &self.input(index as u32 + 1, &chain, &fixed)?, &mut block);
                    if self.mode == KBKDFMode::Feedback {
                        chain.clone_from(&block);
                    }
                    chunk.copy_from_slice(&block[..chunk.len()]);
                }
                Ok(())
            }
        }
    }
}
