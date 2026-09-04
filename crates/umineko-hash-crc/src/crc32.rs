use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CRC32Parameters {
    pub polynomial: u32,
    pub initial: u32,
    pub final_xor: u32,
    pub reflect_input: bool,
    pub reflect_output: bool,
}

impl CRC32Parameters {
    pub const IEEE: Self = Self { polynomial: 0x04C1_1DB7, initial: 0xFFFF_FFFF, final_xor: 0xFFFF_FFFF, reflect_input: true, reflect_output: true };
    pub const BZIP2: Self = Self { polynomial: 0x04C1_1DB7, initial: 0xFFFF_FFFF, final_xor: 0xFFFF_FFFF, reflect_input: false, reflect_output: false };

    pub fn name(&self) -> Option<&'static str> {
        match *self {
            Self::IEEE => Some("CRC-32/IEEE"),
            Self::BZIP2 => Some("CRC-32/BZIP2"),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct CRC32 {
    parameters: CRC32Parameters,
    value: u32,
    backend: ProviderBackend<dyn HashProvider>,
}

impl CRC32 {
    pub const DIGEST_SIZE: usize = 4;

    pub fn new(parameters: CRC32Parameters) -> Self {
        let backend = match parameters.name() {
            Some(name) => HashProviders::backend(&HashProviderRequest::new(name)),
            None => ProviderBackend::Builtin,
        };
        match backend {
            ProviderBackend::Builtin => todo!(),
            backend => Self { parameters, value: 0, backend },
        }
    }

    pub fn parameters(&self) -> CRC32Parameters {
        self.parameters
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> u32 {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; Self::DIGEST_SIZE];
                provider.finalize(*handle, &mut digest);
                u32::from_be_bytes(digest)
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => todo!(),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(parameters: CRC32Parameters, data: &[u8]) -> u32 {
        let mut digest = [0; Self::DIGEST_SIZE];
        match parameters.name().and_then(|name| HashProviders::digest(&HashProviderRequest::new(name), data, &mut digest)) {
            Some(_) => u32::from_be_bytes(digest),
            None => todo!(),
        }
    }
}

impl Clone for CRC32 {
    fn clone(&self) -> Self {
        Self { parameters: self.parameters, value: self.value, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}
