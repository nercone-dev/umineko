use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug)]
pub struct MD2 {
    state: [u8; 48],
    checksum: [u8; 16],
    buffer: [u8; 16],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl MD2 {
    pub const NAME: &'static str = "MD2";
    pub const DIGEST_SIZE: usize = 16;
    pub const BLOCK_SIZE: usize = 16;
    pub const ROUNDS: usize = 18;
    /// The digits of pi, as RFC 1319 lays them out.
    pub const SUBSTITUTION: [u8; 256] = [
        41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19,
        98, 167, 5, 243, 192, 199, 115, 140, 152, 147, 43, 217, 188, 76, 130, 202,
        30, 155, 87, 60, 253, 212, 224, 22, 103, 66, 111, 24, 138, 23, 229, 18,
        190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47, 238, 122,
        169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33,
        128, 127, 93, 154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3,
        255, 25, 48, 179, 72, 165, 181, 209, 215, 94, 146, 42, 172, 86, 170, 198,
        79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226, 156, 116, 4, 241,
        69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2,
        27, 96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15,
        85, 71, 163, 35, 221, 81, 175, 58, 195, 92, 249, 206, 186, 197, 234, 38,
        44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205, 244, 65, 129, 77, 82,
        106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,
        120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57,
        242, 239, 183, 14, 102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10,
        49, 68, 80, 180, 143, 237, 31, 26, 219, 153, 141, 51, 159, 17, 131, 20,
    ];

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { state: [0; 48], checksum: [0; 16], buffer: [0; 16], length: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { state: [0; 48], checksum: [0; 16], buffer: [0; 16], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn compress(state: &mut [u8; 48], block: &[u8; 16]) {
        state[16..32].copy_from_slice(block);
        for index in 0..Self::BLOCK_SIZE {
            state[32 + index] = state[16 + index] ^ state[index];
        }
        let mut carry = 0;
        for round in 0..Self::ROUNDS {
            for value in state.iter_mut() {
                *value ^= Self::SUBSTITUTION[carry as usize];
                carry = *value;
            }
            carry = carry.wrapping_add(round as u8);
        }
    }

    /// Folds a block into the running checksum, which the final block carries.
    pub fn checksum(checksum: &mut [u8; 16], block: &[u8; 16]) {
        let mut last = checksum[Self::BLOCK_SIZE - 1];
        for (value, byte) in checksum.iter_mut().zip(block) {
            *value ^= Self::SUBSTITUTION[(byte ^ last) as usize];
            last = *value;
        }
    }

    pub fn absorb(state: &mut [u8; 48], checksum: &mut [u8; 16], buffer: &mut [u8; 16], length: &mut usize, data: &[u8]) {
        let mut filled = *length % Self::BLOCK_SIZE;
        let mut offset = 0;
        *length = length.wrapping_add(data.len());
        if filled != 0 {
            offset = (Self::BLOCK_SIZE - filled).min(data.len());
            buffer[filled..filled + offset].copy_from_slice(&data[..offset]);
            filled += offset;
            if filled < Self::BLOCK_SIZE {
                return;
            }
            Self::checksum(checksum, buffer);
            Self::compress(state, buffer);
        }
        let mut data = &data[offset..];
        while let Some((block, rest)) = data.split_first_chunk::<{ Self::BLOCK_SIZE }>() {
            Self::checksum(checksum, block);
            Self::compress(state, block);
            data = rest;
        }
        buffer[..data.len()].copy_from_slice(data);
    }

    pub fn squeeze(state: &[u8; 48], checksum: &[u8; 16], buffer: &[u8; 16], length: usize) -> [u8; 16] {
        let mut state = *state;
        let mut checksum = *checksum;
        let filled = length % Self::BLOCK_SIZE;
        let mut block = [(Self::BLOCK_SIZE - filled) as u8; Self::BLOCK_SIZE];
        block[..filled].copy_from_slice(&buffer[..filled]);
        Self::checksum(&mut checksum, &block);
        Self::compress(&mut state, &block);
        Self::compress(&mut state, &checksum);
        let mut digest = [0; Self::DIGEST_SIZE];
        digest.copy_from_slice(&state[..Self::DIGEST_SIZE]);
        digest
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Self::absorb(&mut self.state, &mut self.checksum, &mut self.buffer, &mut self.length, data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> [u8; 16] {
        match &self.backend {
            ProviderBackend::Builtin => Self::squeeze(&self.state, &self.checksum, &self.buffer, self.length),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 16];
                provider.finalize(*handle, &mut digest);
                digest
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => (self.state, self.checksum, self.buffer, self.length) = ([0; 48], [0; 16], [0; 16], 0),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8]) -> [u8; 16] {
        let mut digest = [0; 16];
        match HashProviders::digest(&Self::request(), data, &mut digest) {
            Some(_) => digest,
            None => {
                let mut hash = Self::builtin();
                hash.update(data);
                hash.finalize()
            }
        }
    }
}

impl Clone for MD2 {
    fn clone(&self) -> Self {
        Self { state: self.state, checksum: self.checksum, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for MD2 {
    fn default() -> Self {
        Self::new()
    }
}
