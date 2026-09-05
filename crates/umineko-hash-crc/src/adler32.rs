use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug)]
pub struct Adler32 {
    a: u32,
    b: u32,
    backend: ProviderBackend<dyn HashProvider>,
}

impl Adler32 {
    pub const NAME: &'static str = "Adler-32";
    pub const DIGEST_SIZE: usize = 4;
    pub const MODULO: u32 = 65521;
    /// The longest run of bytes that cannot overflow either sum.
    pub const RUN: usize = 5552;

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { a: 0, b: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { a: 1, b: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    /// Folds `data` into the two running sums, which start at one and zero.
    pub fn absorb(sums: (u32, u32), data: &[u8]) -> (u32, u32) {
        let (mut a, mut b) = sums;
        for run in data.chunks(Self::RUN) {
            for byte in run {
                a += *byte as u32;
                b += a;
            }
            a %= Self::MODULO;
            b %= Self::MODULO;
        }
        (a, b)
    }

    /// Joins the two running sums into the checksum.
    pub fn squeeze(sums: (u32, u32)) -> u32 {
        (sums.1 << 16) | sums.0
    }

    pub fn update(&mut self, data: &[u8]) {
        match &self.backend {
            ProviderBackend::Builtin => (self.a, self.b) = Self::absorb((self.a, self.b), data),
            ProviderBackend::Handle { provider, handle } => provider.update(*handle, data),
        }
    }

    pub fn finalize(self) -> u32 {
        match &self.backend {
            ProviderBackend::Builtin => Self::squeeze((self.a, self.b)),
            ProviderBackend::Handle { provider, handle } => {
                let mut digest = [0; Self::DIGEST_SIZE];
                provider.finalize(*handle, &mut digest);
                u32::from_be_bytes(digest)
            }
        }
    }

    pub fn reset(&mut self) {
        match &self.backend {
            ProviderBackend::Builtin => (self.a, self.b) = (1, 0),
            ProviderBackend::Handle { provider, handle } => provider.reset(*handle),
        }
    }

    pub fn digest(data: &[u8]) -> u32 {
        let mut digest = [0; Self::DIGEST_SIZE];
        match HashProviders::digest(&Self::request(), data, &mut digest) {
            Some(_) => u32::from_be_bytes(digest),
            None => {
                let mut hash = Self::builtin();
                hash.update(data);
                hash.finalize()
            }
        }
    }
}

impl Clone for Adler32 {
    fn clone(&self) -> Self {
        Self { a: self.a, b: self.b, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for Adler32 {
    fn default() -> Self {
        Self::new()
    }
}
