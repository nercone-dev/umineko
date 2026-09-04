use umineko_protocol_ip::IPAddress;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TCPChecksum {
    sum: u32,
}

impl TCPChecksum {
    pub fn new() -> Self {
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

    pub fn compute(source: IPAddress, destination: IPAddress, data: &[u8]) -> u16 {
        todo!()
    }

    pub fn verify(source: IPAddress, destination: IPAddress, data: &[u8]) -> bool {
        todo!()
    }
}

impl Default for TCPChecksum {
    fn default() -> Self {
        Self::new()
    }
}
