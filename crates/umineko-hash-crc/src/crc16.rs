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

    /// The table one polynomial folds its nibbles through.
    pub fn table(&self) -> CRC16Table {
        CRC16Table::new(self.polynomial)
    }

    /// Folds `data` into the register, which starts at `initial` and holds no final transform.
    pub fn absorb(&self, register: u16, data: &[u8]) -> u16 {
        self.table().absorb(register, data, self.reflect_input)
    }

    /// Folds one byte into the register, a bit at a time, which is what a table is built from.
    pub fn fold(&self, register: u16, byte: u8) -> u16 {
        let mut register = register ^ ((byte as u16) << 8);
        for _ in 0..8 {
            register = match register & 0x8000 != 0 {
                true => (register << 1) ^ self.polynomial,
                false => register << 1,
            };
        }
        register
    }

    /// Applies the final transform to a register produced by `absorb`.
    pub fn squeeze(&self, register: u16) -> u16 {
        let register = match self.reflect_output {
            true => register.reverse_bits(),
            false => register,
        };
        register ^ self.final_xor
    }
}

/// The sixteen registers one polynomial folds a nibble into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CRC16Table {
    entries: [u16; 16],
}

impl CRC16Table {
    /// The number of bits one lookup folds, which sets the size of the table.
    pub const BITS: u32 = 4;

    pub const fn new(polynomial: u16) -> Self {
        let mut entries = [0u16; 16];
        let mut index = 0;
        while index < entries.len() {
            let mut register = (index as u16) << (16 - Self::BITS);
            let mut step = 0;
            while step < Self::BITS {
                register = match register & 0x8000 != 0 {
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

    pub fn entries(&self) -> &[u16; 16] {
        &self.entries
    }

    /// Folds one nibble, which the top of the register names.
    pub fn step(&self, register: u16) -> u16 {
        (register << Self::BITS) ^ self.entries[(register >> (16 - Self::BITS)) as usize]
    }

    /// Folds `data` into the register, two nibbles at a time.
    pub fn absorb(&self, register: u16, data: &[u8], reflect: bool) -> u16 {
        let mut register = register;
        for byte in data {
            let byte = match reflect {
                true => byte.reverse_bits(),
                false => *byte,
            };
            register = self.step(self.step(register ^ ((byte as u16) << 8)));
        }
        register
    }
}

#[derive(Debug)]
pub struct CRC16 {
    parameters: CRC16Parameters,
    table: CRC16Table,
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
            ProviderBackend::Builtin => Self::builtin(parameters),
            backend => Self { parameters, table: parameters.table(), value: 0, backend },
        }
    }

    pub fn builtin(parameters: CRC16Parameters) -> Self {
        Self { parameters, table: parameters.table(), value: parameters.initial, backend: ProviderBackend::Builtin }
    }

    pub fn parameters(&self) -> CRC16Parameters {
        self.parameters
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => self.value = self.table.absorb(self.value, data, self.parameters.reflect_input),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> u16 {
        match &self.backend {
            ProviderBackend::Builtin => self.parameters.squeeze(self.value),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; Self::DIGEST_SIZE];
                provider.finalize(*handle, &mut digest);
                u16::from_be_bytes(digest)
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => self.value = self.parameters.initial,
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(parameters: CRC16Parameters, data: &[u8]) -> u16 {
        let mut digest = [0; Self::DIGEST_SIZE];
        match parameters.name().and_then(|name| HashProviders::digest(&HashProviderRequest::new(name), data, &mut digest)) {
            Some(_) => u16::from_be_bytes(digest),
            None => {
                let mut hash = Self::builtin(parameters);
                hash.update(data);
                hash.finalize()
            }
        }
    }
}

impl Clone for CRC16 {
    fn clone(&self) -> Self {
        Self { parameters: self.parameters, table: self.table, value: self.value, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}
