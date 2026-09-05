use alloc::{sync::Arc, vec::Vec};
use core::hash::{Hash, Hasher};
use core::ops::Deref;

#[derive(Debug, Clone)]
pub struct Bytes {
    storage: Option<Arc<[u8]>>,
    offset: usize,
    length: usize,
}

impl Bytes {
    /// Empty bytes, which hold no storage at all.
    pub fn new() -> Self {
        Self { storage: None, offset: 0, length: 0 }
    }

    pub fn copy_from_slice(data: &[u8]) -> Self {
        match data.is_empty() {
            true => Self::new(),
            false => Self { storage: Some(Arc::from(data)), offset: 0, length: data.len() },
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        match &self.storage {
            Some(storage) => &storage[self.offset..self.offset + self.length],
            None => &[],
        }
    }

    pub fn slice(&self, offset: usize, length: usize) -> Option<Self> {
        match offset.checked_add(length) {
            Some(end) if end <= self.length => Some(Self { storage: self.storage.clone(), offset: self.offset + offset, length }),
            _ => None,
        }
    }

    pub fn split(&self, at: usize) -> Option<(Self, Self)> {
        match at <= self.length {
            true => Some((self.slice(0, at)?, self.slice(at, self.length - at)?)),
            false => None,
        }
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.as_slice().to_vec()
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

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl PartialEq for Bytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for Bytes {}

impl Hash for Bytes {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}

impl From<Vec<u8>> for Bytes {
    fn from(data: Vec<u8>) -> Self {
        let length = data.len();
        match length {
            0 => Self::new(),
            length => Self { storage: Some(Arc::from(data)), offset: 0, length },
        }
    }
}

impl From<&[u8]> for Bytes {
    fn from(data: &[u8]) -> Self {
        Self::copy_from_slice(data)
    }
}
