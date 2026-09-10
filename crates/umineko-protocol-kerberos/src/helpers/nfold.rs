use alloc::vec::Vec;
use crate::errors::KerberosError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct KerberosNFold;

impl KerberosNFold {
    pub const ROTATION: u32 = 13;

    pub fn fold(data: &[u8], size: usize) -> Result<Vec<u8>, KerberosError> {
        todo!()
    }
}
