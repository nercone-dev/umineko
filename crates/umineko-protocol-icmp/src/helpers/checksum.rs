use crate::types::ICMPVersion;

use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ICMPChecksum {
    version: ICMPVersion,
    sum: u32,
}

impl ICMPChecksum {
    pub fn new(version: ICMPVersion) -> Self {
        todo!()
    }

    pub fn update(&mut self, data: &[u8]) {
        todo!()
    }

    pub fn update_pseudo_header(&mut self, source: IPAddress, destination: IPAddress, length: u32) {
        todo!()
    }

    pub fn finalize(self) -> u16 {
        todo!()
    }

    pub fn compute(version: ICMPVersion, source: IPAddress, destination: IPAddress, data: &[u8]) -> u16 {
        todo!()
    }

    pub fn verify(version: ICMPVersion, source: IPAddress, destination: IPAddress, data: &[u8]) -> bool {
        todo!()
    }
}
