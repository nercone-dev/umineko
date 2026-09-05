use umineko_hash_hmac::{Digest, HMACFunction};

use crate::pbkdf2::PRF;

impl<D: Digest> PRF for HMACFunction<D> {
    fn output_size(&self) -> usize {
        HMACFunction::output_size(self)
    }

    fn compute(&self, key: &[u8], data: &[u8], output: &mut [u8]) {
        HMACFunction::compute(self, key, data, output);
    }

    fn name(&self) -> Option<&'static str> {
        Some(HMACFunction::name(self))
    }

    fn digest(&self) -> Option<&'static str> {
        Some(HMACFunction::digest(self))
    }
}
