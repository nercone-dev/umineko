use alloc::{sync::Arc, vec::Vec};
use core::ops::Deref;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Bytes {
    storage: Arc<Vec<u8>>,
    offset: usize,
    length: usize,
}

impl Bytes {
    pub fn new() -> Self {
        todo!()
    }

    pub fn copy_from_slice(data: &[u8]) -> Self {
        todo!()
    }

    pub fn as_slice(&self) -> &[u8] {
        todo!()
    }

    pub fn slice(&self, offset: usize, length: usize) -> Option<Self> {
        todo!()
    }

    pub fn split(&self, at: usize) -> Option<(Self, Self)> {
        todo!()
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn into_vec(self) -> Vec<u8> {
        todo!()
    }
}

impl Default for Bytes {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(data: Vec<u8>) -> Self {
        todo!()
    }
}

impl From<&[u8]> for Bytes {
    fn from(data: &[u8]) -> Self {
        Self::copy_from_slice(data)
    }
}
