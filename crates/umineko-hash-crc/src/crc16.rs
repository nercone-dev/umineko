use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CRC16Parameters {
    pub polynomial: u16,
    pub initial: u16,
    pub final_xor: u16,
    pub reflect_input: bool,
    pub reflect_output: bool,
}

impl CRC16Parameters {
    pub const IBM: Self = Self { polynomial: 0x8005, initial: 0x0000, final_xor: 0x0000, reflect_input: true, reflect_output: true };
    pub const CCITT: Self = Self { polynomial: 0x1021, initial: 0xFFFF, final_xor: 0x0000, reflect_input: false, reflect_output: false };
    pub const MODBUS: Self = Self { polynomial: 0x8005, initial: 0xFFFF, final_xor: 0x0000, reflect_input: true, reflect_output: true };

    pub fn name(&self) -> Option<&'static str> {
        match *self {
            Self::IBM => Some("CRC-16/IBM"),
            Self::CCITT => Some("CRC-16/CCITT"),
            Self::MODBUS => Some("CRC-16/MODBUS"),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct CRC16 {
    parameters: CRC16Parameters,
    value: u16,
    backend: ProviderBackend<dyn HashProvider>,
}

impl CRC16 {
    pub const DIGEST_SIZE: usize = 2;

    pub fn new(parameters: CRC16Parameters) -> Self {
        let backend = match parameters.name() {
            Some(name) => HashProviders::backend(&HashProviderRequest::new(name)),
            None => ProviderBackend::Builtin,
        };
        match backend {
            ProviderBackend::Builtin => todo!(),
            backend => Self { parameters, value: 0, backend },
        }
    }

    pub fn parameters(&self) -> CRC16Parameters {
        self.parameters
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> u16 {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; Self::DIGEST_SIZE];
                provider.finalize(*handle, &mut digest);
                u16::from_be_bytes(digest)
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(parameters: CRC16Parameters, data: &[u8]) -> u16 {
        let mut digest = [0; Self::DIGEST_SIZE];
        match parameters.name().and_then(|name| HashProviders::digest(&HashProviderRequest::new(name), data, &mut digest)) {
            Some(_) => u16::from_be_bytes(digest),
            None => todo!(),
        }
    }
}

impl Clone for CRC16 {
    fn clone(&self) -> Self {
        Self { parameters: self.parameters, value: self.value, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}
