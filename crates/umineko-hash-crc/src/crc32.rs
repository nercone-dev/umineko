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

    /// The table one polynomial folds its nibbles through.
    pub fn table(&self) -> CRC32Table {
        CRC32Table::new(self.polynomial)
    }

    /// Folds `data` into the register, which starts at `initial` and holds no final transform.
    pub fn absorb(&self, register: u32, data: &[u8]) -> u32 {
        self.table().absorb(register, data, self.reflect_input)
    }

    /// Folds one byte into the register, a bit at a time, which is what a table is built from.
    pub fn fold(&self, register: u32, byte: u8) -> u32 {
        let mut register = register ^ ((byte as u32) << 24);
        for _ in 0..8 {
            register = match register & 0x8000_0000 != 0 {
                true => (register << 1) ^ self.polynomial,
                false => register << 1,
            };
        }
        register
    }

    /// Applies the final transform to a register produced by `absorb`.
    pub fn squeeze(&self, register: u32) -> u32 {
        let register = match self.reflect_output {
            true => register.reverse_bits(),
            false => register,
        };
        register ^ self.final_xor
    }
}

/// The sixteen registers one polynomial folds a nibble into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CRC32Table {
    entries: [u32; 16],
}

impl CRC32Table {
    /// The number of bits one lookup folds, which sets the size of the table.
    pub const BITS: u32 = 4;

    pub const fn new(polynomial: u32) -> Self {
        let mut entries = [0u32; 16];
        let mut index = 0;
        while index < entries.len() {
            let mut register = (index as u32) << (32 - Self::BITS);
            let mut step = 0;
            while step < Self::BITS {
                register = match register & 0x8000_0000 != 0 {
                    true => (register << 1) ^ polynomial,
                    false => register << 1,
                };
                step += 1;
            }
            entries[index] = register;
            index += 1;
        }
        Self { entries }
    }

    pub fn entries(&self) -> &[u32; 16] {
        &self.entries
    }

    /// Folds one nibble, which the top of the register names.
    pub fn step(&self, register: u32) -> u32 {
        (register << Self::BITS) ^ self.entries[(register >> (32 - Self::BITS)) as usize]
    }

    /// Folds `data` into the register, two nibbles at a time.
    pub fn absorb(&self, register: u32, data: &[u8], reflect: bool) -> u32 {
        let mut register = register;
        for byte in data {
            let byte = match reflect {
                true => byte.reverse_bits(),
                false => *byte,
            };
            register = self.step(self.step(register ^ ((byte as u32) << 24)));
        }
        register
    }
}

#[derive(Debug)]
pub struct CRC32 {
    parameters: CRC32Parameters,
    table: CRC32Table,
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
            ProviderBackend::Builtin => Self::builtin(parameters),
            backend => Self { parameters, table: parameters.table(), value: 0, backend },
        }
    }

    pub fn builtin(parameters: CRC32Parameters) -> Self {
        Self { parameters, table: parameters.table(), value: parameters.initial, backend: ProviderBackend::Builtin }
    }

    pub fn parameters(&self) -> CRC32Parameters {
        self.parameters
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => self.value = self.table.absorb(self.value, data, self.parameters.reflect_input),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> u32 {
        match &self.backend {
            ProviderBackend::Builtin => self.parameters.squeeze(self.value),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; Self::DIGEST_SIZE];
                provider.finalize(*handle, &mut digest);
                u32::from_be_bytes(digest)
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => self.value = self.parameters.initial,
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(parameters: CRC32Parameters, data: &[u8]) -> u32 {
        let mut digest = [0; Self::DIGEST_SIZE];
        match parameters.name().and_then(|name| HashProviders::digest(&HashProviderRequest::new(name), data, &mut digest)) {
            Some(_) => u32::from_be_bytes(digest),
            None => {
                let mut hash = Self::builtin(parameters);
                hash.update(data);
                hash.finalize()
            }
        }
    }
}

impl Clone for CRC32 {
    fn clone(&self) -> Self {
        Self { parameters: self.parameters, table: self.table, value: self.value, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}
