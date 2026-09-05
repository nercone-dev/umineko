use alloc::vec::Vec;
use core::fmt;
use crate::errors::AsconError;

use umineko_helpers::provider::{CipherProviderRequest, CipherProviders, HashProvider, HashProviderRequest, HashProviders, ProviderBackend, ProviderOpening};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ascon {
    AEAD128,
    Hash256,
    XOF128,
    CXOF128,
}

impl Ascon {
    pub const LANES: usize = 5;
    pub const ROUNDS: usize = 12;
    /// The step between the round constants, which start at two hundred and forty.
    pub const STEP: u64 = 15;

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AEAD128 => "Ascon-AEAD128",
            Self::Hash256 => "Ascon-Hash256",
            Self::XOF128 => "Ascon-XOF128",
            Self::CXOF128 => "Ascon-CXOF128",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Ascon-AEAD128" => Some(Self::AEAD128),
            "Ascon-Hash256" => Some(Self::Hash256),
            "Ascon-XOF128" => Some(Self::XOF128),
            "Ascon-CXOF128" => Some(Self::CXOF128),
            _ => None,
        }
    }

    pub fn rate(&self) -> usize {
        match self {
            Self::AEAD128 => 16,
            Self::Hash256 | Self::XOF128 | Self::CXOF128 => 8,
        }
    }

    pub fn rounds(&self) -> usize {
        match self {
            Self::AEAD128 => 8,
            Self::Hash256 | Self::XOF128 | Self::CXOF128 => 12,
        }
    }

    /// The first word of the state, which names the version, the rounds, the tag and the rate.
    pub fn initial(&self) -> u64 {
        let (version, tag) = match self {
            Self::AEAD128 => (1, 128u16),
            Self::Hash256 => (2, 256),
            Self::XOF128 => (3, 0),
            Self::CXOF128 => (4, 0),
        };
        let tag = tag.to_le_bytes();
        u64::from_le_bytes([version, 0, ((self.rounds() as u8) << 4) | Self::ROUNDS as u8, tag[0], tag[1], self.rate() as u8, 0, 0])
    }

    pub fn state(&self) -> [u64; Self::LANES] {
        let mut state = [0; Self::LANES];
        state[0] = self.initial();
        Self::permute(&mut state, Self::ROUNDS);
        state
    }

    /// The substitution and linear layers, over the last `rounds` round constants.
    pub fn permute(state: &mut [u64; Self::LANES], rounds: usize) {
        for round in Self::ROUNDS - rounds..Self::ROUNDS {
            state[2] ^= 0xF0 - round as u64 * Self::STEP;
            state[0] ^= state[4];
            state[4] ^= state[3];
            state[2] ^= state[1];
            let complement: [u64; Self::LANES] = core::array::from_fn(|lane| !state[lane] & state[(lane + 1) % Self::LANES]);
            for (lane, value) in state.iter_mut().enumerate() {
                *value ^= complement[(lane + 1) % Self::LANES];
            }
            state[1] ^= state[0];
            state[0] ^= state[4];
            state[3] ^= state[2];
            state[2] = !state[2];
            state[0] ^= state[0].rotate_right(19) ^ state[0].rotate_right(28);
            state[1] ^= state[1].rotate_right(61) ^ state[1].rotate_right(39);
            state[2] ^= state[2].rotate_right(1) ^ state[2].rotate_right(6);
            state[3] ^= state[3].rotate_right(10) ^ state[3].rotate_right(17);
            state[4] ^= state[4].rotate_right(7) ^ state[4].rotate_right(41);
        }
    }

    pub fn word(block: &[u8], index: usize) -> u64 {
        let mut word = [0; 8];
        let (start, end) = (index * 8, ((index + 1) * 8).min(block.len()));
        word[..end.saturating_sub(start)].copy_from_slice(&block[start.min(block.len())..end]);
        u64::from_le_bytes(word)
    }

    /// One whole block of the rate exclusive ored into the state.
    pub fn mix(state: &mut [u64; Self::LANES], block: &[u8]) {
        for (index, lane) in state.iter_mut().take(block.len().div_ceil(8)).enumerate() {
            *lane ^= Self::word(block, index);
        }
    }

    pub fn bytes(state: &[u64; Self::LANES], rate: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(rate);
        for word in state.iter().take(rate / 8) {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    /// A block of the rate, holding `data` followed by the single bit of padding.
    pub fn padded(data: &[u8], rate: usize) -> Vec<u8> {
        let mut block = data.to_vec();
        block.push(1);
        block.resize(rate, 0);
        block
    }

    /// Every whole block absorbed, and the trailing bytes returned for the padded block.
    pub fn absorb<'a>(&self, state: &mut [u64; Self::LANES], data: &'a [u8]) -> &'a [u8] {
        let rate = self.rate();
        let whole = data.len() / rate * rate;
        for block in data[..whole].chunks_exact(rate) {
            Self::mix(state, block);
            Self::permute(state, self.rounds());
        }
        &data[whole..]
    }

    pub fn squeeze(&self, state: &mut [u64; Self::LANES], digest: &mut [u8]) {
        for part in digest.chunks_mut(self.rate()) {
            let block = Self::bytes(state, self.rate());
            part.copy_from_slice(&block[..part.len()]);
            Self::permute(state, self.rounds());
        }
    }

    /// One buffered sponge fed with `data`, keeping the trailing bytes for the padded block.
    pub fn gather(variant: Ascon, state: &mut [u64; Self::LANES], buffer: &mut [u8; 8], length: &mut usize, data: &[u8]) {
        let mut data = data;
        while !data.is_empty() {
            if *length == variant.rate() {
                Self::mix(state, buffer);
                Self::permute(state, variant.rounds());
                *length = 0;
            }
            let taken = (variant.rate() - *length).min(data.len());
            buffer[*length..*length + taken].copy_from_slice(&data[..taken]);
            *length += taken;
            data = &data[taken..];
        }
    }

    /// The padded block absorbed and the state squeezed into `digest`.
    pub fn scatter(variant: Ascon, state: [u64; Self::LANES], rest: &[u8], digest: &mut [u8]) {
        let mut state = state;
        Self::mix(&mut state, &Self::padded(rest, variant.rate()));
        Self::permute(&mut state, variant.rounds());
        variant.squeeze(&mut state, digest);
    }

    pub fn different(left: &[u8], right: &[u8]) -> bool {
        let mut difference = (left.len() != right.len()) as u8;
        for (first, second) in left.iter().zip(right) {
            difference |= first ^ second;
        }
        difference != 0
    }
}

impl fmt::Display for Ascon {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsconAEAD128 {
    key: [u8; 16],
    state: [u64; Ascon::LANES],
}

impl AsconAEAD128 {
    pub const VARIANT: Ascon = Ascon::AEAD128;
    pub const NAME: &'static str = "Ascon-AEAD128";
    pub const KEY_SIZE: usize = 16;
    pub const NONCE_SIZE: usize = 16;
    pub const TAG_SIZE: usize = 16;
    pub const RATE: usize = 16;

    pub fn new(key: &[u8; 16]) -> Self {
        Self { key: *key, state: [Self::VARIANT.initial(), Ascon::word(key, 0), Ascon::word(key, 1), 0, 0] }
    }

    pub fn request<'a>(&'a self, nonce: &'a [u8; 16], associated: &'a [u8]) -> CipherProviderRequest<'a> {
        CipherProviderRequest::new(Self::NAME, &self.key).with_nonce(nonce).with_associated(associated)
    }

    /// The state after the key and the nonce, with the key folded in once more.
    pub fn initial(&self, nonce: &[u8; 16]) -> [u64; Ascon::LANES] {
        let mut state = self.state;
        state[3] = Ascon::word(nonce, 0);
        state[4] = Ascon::word(nonce, 1);
        Ascon::permute(&mut state, Ascon::ROUNDS);
        state[3] ^= self.state[1];
        state[4] ^= self.state[2];
        state
    }

    pub fn associate(&self, state: &mut [u64; Ascon::LANES], associated: &[u8]) {
        if !associated.is_empty() {
            let rest = Self::VARIANT.absorb(state, associated);
            Ascon::mix(state, &Ascon::padded(rest, Self::RATE));
            Ascon::permute(state, Self::VARIANT.rounds());
        }
        state[4] ^= 1 << 63;
    }

    pub fn tag(&self, state: &mut [u64; Ascon::LANES]) -> [u8; 16] {
        state[2] ^= self.state[1];
        state[3] ^= self.state[2];
        Ascon::permute(state, Ascon::ROUNDS);
        let mut tag = [0; 16];
        tag[..8].copy_from_slice(&(state[3] ^ self.state[1]).to_le_bytes());
        tag[8..].copy_from_slice(&(state[4] ^ self.state[2]).to_le_bytes());
        tag
    }

    pub fn encrypt(&self, nonce: &[u8; 16], associated: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AsconError> {
        match CipherProviders::encrypt(&self.request(nonce, associated), plaintext)? {
            Some(ciphertext) => Ok(ciphertext),
            None => {
                let mut state = self.initial(nonce);
                self.associate(&mut state, associated);
                let mut ciphertext = Vec::with_capacity(plaintext.len() + Self::TAG_SIZE);
                let whole = plaintext.len() / Self::RATE * Self::RATE;
                for block in plaintext[..whole].chunks_exact(Self::RATE) {
                    Ascon::mix(&mut state, block);
                    ciphertext.extend_from_slice(&Ascon::bytes(&state, Self::RATE));
                    Ascon::permute(&mut state, Self::VARIANT.rounds());
                }
                let rest = &plaintext[whole..];
                Ascon::mix(&mut state, &Ascon::padded(rest, Self::RATE));
                ciphertext.extend_from_slice(&Ascon::bytes(&state, Self::RATE)[..rest.len()]);
                ciphertext.extend_from_slice(&self.tag(&mut state));
                Ok(ciphertext)
            }
        }
    }

    pub fn decrypt(&self, nonce: &[u8; 16], associated: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, AsconError> {
        match CipherProviders::decrypt(&self.request(nonce, associated), ciphertext)? {
            Some(plaintext) => Ok(plaintext),
            None => {
                if ciphertext.len() < Self::TAG_SIZE {
                    return Err(AsconError::Length);
                }
                let (ciphertext, expected) = ciphertext.split_at(ciphertext.len() - Self::TAG_SIZE);
                let mut state = self.initial(nonce);
                self.associate(&mut state, associated);
                let mut plaintext = Vec::with_capacity(ciphertext.len());
                let whole = ciphertext.len() / Self::RATE * Self::RATE;
                for block in ciphertext[..whole].chunks_exact(Self::RATE) {
                    let keystream = Ascon::bytes(&state, Self::RATE);
                    plaintext.extend(block.iter().zip(&keystream).map(|(byte, key)| byte ^ key));
                    Ascon::mix(&mut state, &keystream);
                    Ascon::mix(&mut state, block);
                    Ascon::permute(&mut state, Self::VARIANT.rounds());
                }
                let rest = &ciphertext[whole..];
                let mut keystream = Ascon::bytes(&state, Self::RATE);
                plaintext.extend(rest.iter().zip(&keystream).map(|(byte, key)| byte ^ key));
                let mut block = keystream.clone();
                block[..rest.len()].copy_from_slice(rest);
                block[rest.len()] ^= 1;
                keystream.iter_mut().zip(&block).for_each(|(key, byte)| *key ^= byte);
                Ascon::mix(&mut state, &keystream);
                match Ascon::different(&self.tag(&mut state), expected) {
                    true => Err(AsconError::Authentication),
                    false => Ok(plaintext),
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct AsconHash256 {
    state: [u64; Ascon::LANES],
    buffer: [u8; 8],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl AsconHash256 {
    pub const VARIANT: Ascon = Ascon::Hash256;
    pub const NAME: &'static str = "Ascon-Hash256";
    pub const DIGEST_SIZE: usize = 32;
    pub const RATE: usize = 8;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { state: [0; Ascon::LANES], buffer: [0; 8], length: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { state: Self::VARIANT.state(), buffer: [0; 8], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Ascon::gather(Self::VARIANT, &mut self.state, &mut self.buffer, &mut self.length, data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> [u8; 32] {
        let mut digest = [0; 32];
        match &self.backend {
            ProviderBackend::Builtin => Ascon::scatter(Self::VARIANT, self.state, &self.buffer[..self.length], &mut digest),
            ProviderBackend::Handle { provider, handle } => {
                provider.finalize(*handle, &mut digest);
            }
        }
        digest
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => (self.state, self.buffer, self.length) = (Self::VARIANT.state(), [0; 8], 0),
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

impl Clone for AsconHash256 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for AsconHash256 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct AsconXOF128 {
    state: [u64; Ascon::LANES],
    buffer: [u8; 8],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl AsconXOF128 {
    pub const VARIANT: Ascon = Ascon::XOF128;
    pub const NAME: &'static str = "Ascon-XOF128";
    pub const RATE: usize = 8;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { state: [0; Ascon::LANES], buffer: [0; 8], length: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { state: Self::VARIANT.state(), buffer: [0; 8], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Ascon::gather(Self::VARIANT, &mut self.state, &mut self.buffer, &mut self.length, data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self, digest: &mut [u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Ascon::scatter(Self::VARIANT, self.state, &self.buffer[..self.length], digest),
            ProviderBackend::Handle { provider, handle } => {
                provider.finalize(*handle, digest);
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => (self.state, self.buffer, self.length) = (Self::VARIANT.state(), [0; 8], 0),
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

impl Clone for AsconXOF128 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for AsconXOF128 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct AsconCXOF128 {
    state: [u64; Ascon::LANES],
    initial: [u64; Ascon::LANES],
    buffer: [u8; 8],
    length: usize,
    backend: ProviderBackend<dyn HashProvider>,
}

impl AsconCXOF128 {
    pub const VARIANT: Ascon = Ascon::CXOF128;
    pub const NAME: &'static str = "Ascon-CXOF128";
    pub const RATE: usize = 8;
    pub const MAX_CUSTOMIZATION_SIZE: usize = 256;

    pub fn new(customization: &[u8]) -> Result<Self, AsconError> {
        if customization.len() > Self::MAX_CUSTOMIZATION_SIZE {
            return Err(AsconError::Length);
        }
        match HashProviders::open(&Self::request(customization))? {
            Some(ProviderOpening { provider, handle }) => Ok(Self { state: [0; Ascon::LANES], initial: [0; Ascon::LANES], buffer: [0; 8], length: 0, backend: ProviderBackend::Handle { provider, handle } }),
            None => Ok(Self::builtin(customization)),
        }
    }

    /// The state after the length of the customization string and the string itself.
    pub fn builtin(customization: &[u8]) -> Self {
        let mut state = Self::VARIANT.state();
        let mut blocks = (customization.len() as u64 * 8).to_le_bytes().to_vec();
        blocks.extend_from_slice(customization);
        blocks.extend_from_slice(&Ascon::padded(&[], Self::RATE - customization.len() % Self::RATE));
        for block in blocks.chunks_exact(Self::RATE) {
            Ascon::mix(&mut state, block);
            Ascon::permute(&mut state, Self::VARIANT.rounds());
        }
        Self { state, initial: state, buffer: [0; 8], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request(customization: &[u8]) -> HashProviderRequest<'_> {
        HashProviderRequest::new(Self::NAME).with_customization(customization)
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Ascon::gather(Self::VARIANT, &mut self.state, &mut self.buffer, &mut self.length, data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self, digest: &mut [u8]) {
        match &self.backend {
            ProviderBackend::Builtin => Ascon::scatter(Self::VARIANT, self.state, &self.buffer[..self.length], digest),
            ProviderBackend::Handle { provider, handle } => {
                provider.finalize(*handle, digest);
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => (self.state, self.buffer, self.length) = (self.initial, [0; 8], 0),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(customization: &[u8], data: &[u8], digest: &mut [u8]) -> Result<(), AsconError> {
        if customization.len() > Self::MAX_CUSTOMIZATION_SIZE {
            return Err(AsconError::Length);
        }
        match HashProviders::try_digest(&Self::request(customization), data, digest)? {
            Some(_) => Ok(()),
            None => {
                let mut hash = Self::builtin(customization);
                hash.update(data);
                hash.finalize(digest);
                Ok(())
            }
        }
    }
}

impl Clone for AsconCXOF128 {
    fn clone(&self) -> Self {
        Self { state: self.state, initial: self.initial, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}
