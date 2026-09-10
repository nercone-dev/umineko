use crate::types::{IPAddress, IPProtocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IPChecksum {
    sum: u32,
}

impl IPChecksum {
    pub fn new() -> Self {
        todo!()
    }

    pub fn update(&mut self, data: &[u8]) {
        todo!()
    }

    pub fn update_pseudo_header(&mut self, source: IPAddress, destination: IPAddress, protocol: IPProtocol, length: u32) {
        todo!()
    }

    pub fn finalize(self) -> u16 {
        todo!()
    }

    pub fn compute(data: &[u8]) -> u16 {
        todo!()
    }

    pub fn verify(data: &[u8]) -> bool {
        todo!()
    }
}

impl Default for IPChecksum {
    fn default() -> Self {
        Self::new()
    }
}
