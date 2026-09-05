use core::fmt;

use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SHA3 {
    V224,
    V256,
    V384,
    V512,
}

impl SHA3 {
    pub const ROUNDS: usize = 24;
    pub const LANES: usize = 25;
    /// The widest rate any Keccak sponge in this crate absorbs at once.
    pub const RATE: usize = 168;
    /// The domain separation SHA-3 appends before the pad, as FIPS 202 sets it out.
    pub const DOMAIN: u8 = 0x06;
    pub const ADDITIONS: [u64; 24] = [
        0x0000_0000_0000_0001, 0x0000_0000_0000_8082, 0x8000_0000_0000_808A, 0x8000_0000_8000_8000,
        0x0000_0000_0000_808B, 0x0000_0000_8000_0001, 0x8000_0000_8000_8081, 0x8000_0000_0000_8009,
        0x0000_0000_0000_008A, 0x0000_0000_0000_0088, 0x0000_0000_8000_8009, 0x0000_0000_8000_000A,
        0x0000_0000_8000_808B, 0x8000_0000_0000_008B, 0x8000_0000_0000_8089, 0x8000_0000_0000_8003,
        0x8000_0000_0000_8002, 0x8000_0000_0000_0080, 0x0000_0000_0000_800A, 0x8000_0000_8000_000A,
        0x8000_0000_8000_8081, 0x8000_0000_0000_8080, 0x0000_0000_8000_0001, 0x8000_0000_8000_8008,
    ];

    /// The lane each step of the rho and pi steps carries its word into.
    pub const LANES_ORDER: [usize; 24] = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];
    /// The rotation each of those steps applies.
    pub const ROTATIONS: [u32; 24] = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];

    pub fn digest_size(&self) -> usize {
        match self {
            Self::V224 => 28,
            Self::V256 => 32,
            Self::V384 => 48,
            Self::V512 => 64,
        }
    }

    pub fn block_size(&self) -> usize {
        match self {
            Self::V224 => 144,
            Self::V256 => 136,
            Self::V384 => 104,
            Self::V512 => 72,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V224 => "SHA3-224",
            Self::V256 => "SHA3-256",
            Self::V384 => "SHA3-384",
            Self::V512 => "SHA3-512",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "SHA3-224" => Some(Self::V224),
            "SHA3-256" => Some(Self::V256),
            "SHA3-384" => Some(Self::V384),
            "SHA3-512" => Some(Self::V512),
            _ => None,
        }
    }

    /// The Keccak-f[1600] permutation, which every sponge in this crate shares.
    pub fn permute(state: &mut [u64; 25]) {
        for round in 0..Self::ROUNDS {
            let mut parity = [0u64; 5];
            for (column, value) in parity.iter_mut().enumerate() {
                *value = state[column] ^ state[column + 5] ^ state[column + 10] ^ state[column + 15] ^ state[column + 20];
            }
            for column in 0..5 {
                let step = parity[(column + 4) % 5] ^ parity[(column + 1) % 5].rotate_left(1);
                for row in 0..5 {
                    state[column + 5 * row] ^= step;
                }
            }
            let mut carried = state[1];
            for (lane, rotation) in Self::LANES_ORDER.into_iter().zip(Self::ROTATIONS) {
                let held = state[lane];
                state[lane] = carried.rotate_left(rotation);
                carried = held;
            }
            for row in 0..5 {
                let held: [u64; 5] = core::array::from_fn(|column| state[column + 5 * row]);
                for column in 0..5 {
                    state[column + 5 * row] = held[column] ^ (!held[(column + 1) % 5] & held[(column + 2) % 5]);
                }
            }
            state[0] ^= Self::ADDITIONS[round];
        }
    }

    /// Folds one rate sized block into the state and permutes it.
    pub fn fold(state: &mut [u64; 25], block: &[u8]) {
        for (lane, chunk) in state.iter_mut().zip(block.chunks_exact(8)) {
            *lane ^= u64::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7]]);
        }
        Self::permute(state);
    }

    pub fn absorb(state: &mut [u64; 25], buffer: &mut [u8], length: &mut usize, rate: usize, data: &[u8]) {
        let mut offset = 0;
        if *length != 0 {
            offset = (rate - *length).min(data.len());
            buffer[*length..*length + offset].copy_from_slice(&data[..offset]);
            *length += offset;
            if *length < rate {
                return;
            }
            Self::fold(state, &buffer[..rate]);
            *length = 0;
        }
        while data.len() - offset >= rate {
            Self::fold(state, &data[offset..offset + rate]);
            offset += rate;
        }
        buffer[..data.len() - offset].copy_from_slice(&data[offset..]);
        *length = data.len() - offset;
    }

    pub fn squeeze(state: &[u64; 25], buffer: &[u8], length: usize, rate: usize, domain: u8, digest: &mut [u8]) {
        let mut state = *state;
        let mut block = [0; Self::RATE];
        block[..length].copy_from_slice(&buffer[..length]);
        block[length] ^= domain;
        block[rate - 1] ^= 0x80;
        Self::fold(&mut state, &block[..rate]);
        let mut offset = 0;
        while offset < digest.len() {
            let taken = (digest.len() - offset).min(rate);
            for (index, byte) in digest[offset..offset + taken].iter_mut().enumerate() {
                *byte = (state[index / 8] >> (8 * (index % 8))) as u8;
            }
            offset += taken;
            if offset < digest.len() {
                Self::permute(&mut state);
            }
        }
    }
}

impl fmt::Display for SHA3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct SHA3_224 {
    state: [u64; 25],
    buffer: [u8; 144],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA3_224 {
    pub const NAME: &'static str = "SHA3-224";
    pub const DIGEST_SIZE: usize = 28;
    pub const BLOCK_SIZE: usize = 144;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { state: [0; 25], buffer: [0; 144], length: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { state: [0; 25], buffer: [0; 144], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn absorb(state: &mut [u64; 25], buffer: &mut [u8; 144], length: &mut usize, data: &[u8]) {
        SHA3::absorb(state, buffer, length, Self::BLOCK_SIZE, data);
    }

    pub fn squeeze(state: &[u64; 25], buffer: &[u8; 144], length: usize) -> [u8; 28] {
        let mut digest = [0; 28];
        SHA3::squeeze(state, buffer, length, Self::BLOCK_SIZE, SHA3::DOMAIN, &mut digest);
        digest
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Self::absorb(&mut self.state, &mut self.buffer, &mut self.length, data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> [u8; 28] {
        match &self.backend {
            ProviderBackend::Builtin => Self::squeeze(&self.state, &self.buffer, self.length),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 28];
                provider.finalize(*handle, &mut digest);
                digest
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => (self.state, self.buffer, self.length) = ([0; 25], [0; 144], 0),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8]) -> [u8; 28] {
        let mut digest = [0; 28];
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

impl Clone for SHA3_224 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA3_224 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SHA3_256 {
    state: [u64; 25],
    buffer: [u8; 136],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA3_256 {
    pub const NAME: &'static str = "SHA3-256";
    pub const DIGEST_SIZE: usize = 32;
    pub const BLOCK_SIZE: usize = 136;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { state: [0; 25], buffer: [0; 136], length: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { state: [0; 25], buffer: [0; 136], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn absorb(state: &mut [u64; 25], buffer: &mut [u8; 136], length: &mut usize, data: &[u8]) {
        SHA3::absorb(state, buffer, length, Self::BLOCK_SIZE, data);
    }

    pub fn squeeze(state: &[u64; 25], buffer: &[u8; 136], length: usize) -> [u8; 32] {
        let mut digest = [0; 32];
        SHA3::squeeze(state, buffer, length, Self::BLOCK_SIZE, SHA3::DOMAIN, &mut digest);
        digest
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Self::absorb(&mut self.state, &mut self.buffer, &mut self.length, data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> [u8; 32] {
        match &self.backend {
            ProviderBackend::Builtin => Self::squeeze(&self.state, &self.buffer, self.length),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 32];
                provider.finalize(*handle, &mut digest);
                digest
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => (self.state, self.buffer, self.length) = ([0; 25], [0; 136], 0),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8]) -> [u8; 32] {
        let mut digest = [0; 32];
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

impl Clone for SHA3_256 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA3_256 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SHA3_384 {
    state: [u64; 25],
    buffer: [u8; 104],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA3_384 {
    pub const NAME: &'static str = "SHA3-384";
    pub const DIGEST_SIZE: usize = 48;
    pub const BLOCK_SIZE: usize = 104;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { state: [0; 25], buffer: [0; 104], length: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { state: [0; 25], buffer: [0; 104], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn absorb(state: &mut [u64; 25], buffer: &mut [u8; 104], length: &mut usize, data: &[u8]) {
        SHA3::absorb(state, buffer, length, Self::BLOCK_SIZE, data);
    }

    pub fn squeeze(state: &[u64; 25], buffer: &[u8; 104], length: usize) -> [u8; 48] {
        let mut digest = [0; 48];
        SHA3::squeeze(state, buffer, length, Self::BLOCK_SIZE, SHA3::DOMAIN, &mut digest);
        digest
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Self::absorb(&mut self.state, &mut self.buffer, &mut self.length, data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> [u8; 48] {
        match &self.backend {
            ProviderBackend::Builtin => Self::squeeze(&self.state, &self.buffer, self.length),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 48];
                provider.finalize(*handle, &mut digest);
                digest
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => (self.state, self.buffer, self.length) = ([0; 25], [0; 104], 0),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8]) -> [u8; 48] {
        let mut digest = [0; 48];
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

impl Clone for SHA3_384 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA3_384 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SHA3_512 {
    state: [u64; 25],
    buffer: [u8; 72],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA3_512 {
    pub const NAME: &'static str = "SHA3-512";
    pub const DIGEST_SIZE: usize = 64;
    pub const BLOCK_SIZE: usize = 72;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { state: [0; 25], buffer: [0; 72], length: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { state: [0; 25], buffer: [0; 72], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn absorb(state: &mut [u64; 25], buffer: &mut [u8; 72], length: &mut usize, data: &[u8]) {
        SHA3::absorb(state, buffer, length, Self::BLOCK_SIZE, data);
    }

    pub fn squeeze(state: &[u64; 25], buffer: &[u8; 72], length: usize) -> [u8; 64] {
        let mut digest = [0; 64];
        SHA3::squeeze(state, buffer, length, Self::BLOCK_SIZE, SHA3::DOMAIN, &mut digest);
        digest
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Self::absorb(&mut self.state, &mut self.buffer, &mut self.length, data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> [u8; 64] {
        match &self.backend {
            ProviderBackend::Builtin => Self::squeeze(&self.state, &self.buffer, self.length),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; 64];
                provider.finalize(*handle, &mut digest);
                digest
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => (self.state, self.buffer, self.length) = ([0; 25], [0; 72], 0),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8]) -> [u8; 64] {
        let mut digest = [0; 64];
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

impl Clone for SHA3_512 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA3_512 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SHAKE {
    V128,
    V256,
}

impl SHAKE {
    /// The domain separation an extendable output function appends before the pad.
    pub const DOMAIN: u8 = 0x1F;

    pub fn digest_size(&self) -> usize {
        match self {
            Self::V128 => 32,
            Self::V256 => 64,
        }
    }

    pub fn block_size(&self) -> usize {
        match self {
            Self::V128 => 168,
            Self::V256 => 136,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V128 => "SHAKE128",
            Self::V256 => "SHAKE256",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "SHAKE128" => Some(Self::V128),
            "SHAKE256" => Some(Self::V256),
            _ => None,
        }
    }
}

impl fmt::Display for SHAKE {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct SHAKE128 {
    state: [u64; 25],
    buffer: [u8; 168],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHAKE128 {
    pub const NAME: &'static str = "SHAKE128";
    pub const BLOCK_SIZE: usize = 168;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { state: [0; 25], buffer: [0; 168], length: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { state: [0; 25], buffer: [0; 168], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn absorb(state: &mut [u64; 25], buffer: &mut [u8; 168], length: &mut usize, data: &[u8]) {
        SHA3::absorb(state, buffer, length, Self::BLOCK_SIZE, data);
    }

    pub fn squeeze(state: &[u64; 25], buffer: &[u8; 168], length: usize, digest: &mut [u8]) {
        SHA3::squeeze(state, buffer, length, Self::BLOCK_SIZE, SHAKE::DOMAIN, digest);
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Self::absorb(&mut self.state, &mut self.buffer, &mut self.length, data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self, digest: &mut [u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Self::squeeze(&self.state, &self.buffer, self.length, digest),
            ProviderBackend::Handle { provider, handle } => {
                provider.finalize(*handle, digest);
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => (self.state, self.buffer, self.length) = ([0; 25], [0; 168], 0),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8], digest: &mut [u8]) {
        match HashProviders::digest(&Self::request(), data, digest) {
            Some(_) => {}
            None => {
                let mut hash = Self::builtin();
                hash.update(data);
                hash.finalize(digest);
            }
        }
    }
}

impl Clone for SHAKE128 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHAKE128 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SHAKE256 {
    state: [u64; 25],
    buffer: [u8; 136],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHAKE256 {
    pub const NAME: &'static str = "SHAKE256";
    pub const BLOCK_SIZE: usize = 136;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { state: [0; 25], buffer: [0; 136], length: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { state: [0; 25], buffer: [0; 136], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn absorb(state: &mut [u64; 25], buffer: &mut [u8; 136], length: &mut usize, data: &[u8]) {
        SHA3::absorb(state, buffer, length, Self::BLOCK_SIZE, data);
    }

    pub fn squeeze(state: &[u64; 25], buffer: &[u8; 136], length: usize, digest: &mut [u8]) {
        SHA3::squeeze(state, buffer, length, Self::BLOCK_SIZE, SHAKE::DOMAIN, digest);
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Self::absorb(&mut self.state, &mut self.buffer, &mut self.length, data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self, digest: &mut [u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Self::squeeze(&self.state, &self.buffer, self.length, digest),
            ProviderBackend::Handle { provider, handle } => {
                provider.finalize(*handle, digest);
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => (self.state, self.buffer, self.length) = ([0; 25], [0; 136], 0),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8], digest: &mut [u8]) {
        match HashProviders::digest(&Self::request(), data, digest) {
            Some(_) => {}
            None => {
                let mut hash = Self::builtin();
                hash.update(data);
                hash.finalize(digest);
            }
        }
    }
}

impl Clone for SHAKE256 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHAKE256 {
    fn default() -> Self {
        Self::new()
    }
}
