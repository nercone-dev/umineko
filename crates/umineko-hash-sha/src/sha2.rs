use core::fmt;

use umineko_helpers::provider::{HashProvider, HashProviderRequest, HashProviders, ProviderBackend};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SHA2 {
    V224,
    V256,
    V384,
    V512,
    V512_224,
    V512_256,
}

impl SHA2 {
    pub const ROUNDS32: usize = 64;
    pub const ROUNDS64: usize = 80;
    pub const BLOCK_SIZE32: usize = 64;
    pub const BLOCK_SIZE64: usize = 128;
    /// The cube roots of the first sixty-four primes, in thirty-two bit words.
    pub const ADDITIONS32: [u32; 64] = [
        0x428A_2F98, 0x7137_4491, 0xB5C0_FBCF, 0xE9B5_DBA5, 0x3956_C25B, 0x59F1_11F1, 0x923F_82A4, 0xAB1C_5ED5,
        0xD807_AA98, 0x1283_5B01, 0x2431_85BE, 0x550C_7DC3, 0x72BE_5D74, 0x80DE_B1FE, 0x9BDC_06A7, 0xC19B_F174,
        0xE49B_69C1, 0xEFBE_4786, 0x0FC1_9DC6, 0x240C_A1CC, 0x2DE9_2C6F, 0x4A74_84AA, 0x5CB0_A9DC, 0x76F9_88DA,
        0x983E_5152, 0xA831_C66D, 0xB003_27C8, 0xBF59_7FC7, 0xC6E0_0BF3, 0xD5A7_9147, 0x06CA_6351, 0x1429_2967,
        0x27B7_0A85, 0x2E1B_2138, 0x4D2C_6DFC, 0x5338_0D13, 0x650A_7354, 0x766A_0ABB, 0x81C2_C92E, 0x9272_2C85,
        0xA2BF_E8A1, 0xA81A_664B, 0xC24B_8B70, 0xC76C_51A3, 0xD192_E819, 0xD699_0624, 0xF40E_3585, 0x106A_A070,
        0x19A4_C116, 0x1E37_6C08, 0x2748_774C, 0x34B0_BCB5, 0x391C_0CB3, 0x4ED8_AA4A, 0x5B9C_CA4F, 0x682E_6FF3,
        0x748F_82EE, 0x78A5_636F, 0x84C8_7814, 0x8CC7_0208, 0x90BE_FFFA, 0xA450_6CEB, 0xBEF9_A3F7, 0xC671_78F2,
    ];
    /// The cube roots of the first eighty primes, in sixty-four bit words.
    pub const ADDITIONS64: [u64; 80] = [
        0x428A_2F98_D728_AE22, 0x7137_4491_23EF_65CD, 0xB5C0_FBCF_EC4D_3B2F, 0xE9B5_DBA5_8189_DBBC,
        0x3956_C25B_F348_B538, 0x59F1_11F1_B605_D019, 0x923F_82A4_AF19_4F9B, 0xAB1C_5ED5_DA6D_8118,
        0xD807_AA98_A303_0242, 0x1283_5B01_4570_6FBE, 0x2431_85BE_4EE4_B28C, 0x550C_7DC3_D5FF_B4E2,
        0x72BE_5D74_F27B_896F, 0x80DE_B1FE_3B16_96B1, 0x9BDC_06A7_25C7_1235, 0xC19B_F174_CF69_2694,
        0xE49B_69C1_9EF1_4AD2, 0xEFBE_4786_384F_25E3, 0x0FC1_9DC6_8B8C_D5B5, 0x240C_A1CC_77AC_9C65,
        0x2DE9_2C6F_592B_0275, 0x4A74_84AA_6EA6_E483, 0x5CB0_A9DC_BD41_FBD4, 0x76F9_88DA_8311_53B5,
        0x983E_5152_EE66_DFAB, 0xA831_C66D_2DB4_3210, 0xB003_27C8_98FB_213F, 0xBF59_7FC7_BEEF_0EE4,
        0xC6E0_0BF3_3DA8_8FC2, 0xD5A7_9147_930A_A725, 0x06CA_6351_E003_826F, 0x1429_2967_0A0E_6E70,
        0x27B7_0A85_46D2_2FFC, 0x2E1B_2138_5C26_C926, 0x4D2C_6DFC_5AC4_2AED, 0x5338_0D13_9D95_B3DF,
        0x650A_7354_8BAF_63DE, 0x766A_0ABB_3C77_B2A8, 0x81C2_C92E_47ED_AEE6, 0x9272_2C85_1482_353B,
        0xA2BF_E8A1_4CF1_0364, 0xA81A_664B_BC42_3001, 0xC24B_8B70_D0F8_9791, 0xC76C_51A3_0654_BE30,
        0xD192_E819_D6EF_5218, 0xD699_0624_5565_A910, 0xF40E_3585_5771_202A, 0x106A_A070_32BB_D1B8,
        0x19A4_C116_B8D2_D0C8, 0x1E37_6C08_5141_AB53, 0x2748_774C_DF8E_EB99, 0x34B0_BCB5_E19B_48A8,
        0x391C_0CB3_C5C9_5A63, 0x4ED8_AA4A_E341_8ACB, 0x5B9C_CA4F_7763_E373, 0x682E_6FF3_D6B2_B8A3,
        0x748F_82EE_5DEF_B2FC, 0x78A5_636F_4317_2F60, 0x84C8_7814_A1F0_AB72, 0x8CC7_0208_1A64_39EC,
        0x90BE_FFFA_2363_1E28, 0xA450_6CEB_DE82_BDE9, 0xBEF9_A3F7_B2C6_7915, 0xC671_78F2_E372_532B,
        0xCA27_3ECE_EA26_619C, 0xD186_B8C7_21C0_C207, 0xEADA_7DD6_CDE0_EB1E, 0xF57D_4F7F_EE6E_D178,
        0x06F0_67AA_7217_6FBA, 0x0A63_7DC5_A2C8_98A6, 0x113F_9804_BEF9_0DAE, 0x1B71_0B35_131C_471B,
        0x28DB_77F5_2304_7D84, 0x32CA_AB7B_40C7_2493, 0x3C9E_BE0A_15C9_BEBC, 0x431D_67C4_9C10_0D4C,
        0x4CC5_D4BE_CB3E_42B6, 0x597F_299C_FC65_7E2A, 0x5FCB_6FAB_3AD6_FAEC, 0x6C44_198C_4A47_5817,
    ];

    pub fn digest_size(&self) -> usize {
        match self {
            Self::V224 => 28,
            Self::V256 => 32,
            Self::V384 => 48,
            Self::V512 => 64,
            Self::V512_224 => 28,
            Self::V512_256 => 32,
        }
    }

    pub fn block_size(&self) -> usize {
        match self {
            Self::V224 => 64,
            Self::V256 => 64,
            Self::V384 => 128,
            Self::V512 => 128,
            Self::V512_224 => 128,
            Self::V512_256 => 128,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V224 => "SHA-224",
            Self::V256 => "SHA-256",
            Self::V384 => "SHA-384",
            Self::V512 => "SHA-512",
            Self::V512_224 => "SHA-512/224",
            Self::V512_256 => "SHA-512/256",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "SHA-224" => Some(Self::V224),
            "SHA-256" => Some(Self::V256),
            "SHA-384" => Some(Self::V384),
            "SHA-512" => Some(Self::V512),
            "SHA-512/224" => Some(Self::V512_224),
            "SHA-512/256" => Some(Self::V512_256),
            _ => None,
        }
    }

    /// The message word of step `index`, which the sixteen words before it name.
    pub fn schedule32(words: &mut [u32; 16], index: usize) -> u32 {
        let (previous, recent) = (words[(index + 1) % 16], words[(index + 14) % 16]);
        let low = previous.rotate_right(7) ^ previous.rotate_right(18) ^ (previous >> 3);
        let high = recent.rotate_right(17) ^ recent.rotate_right(19) ^ (recent >> 10);
        words[index % 16] = words[index % 16].wrapping_add(low).wrapping_add(words[(index + 9) % 16]).wrapping_add(high);
        words[index % 16]
    }

    pub fn compress32(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut words = [0u32; 16];
        for (word, chunk) in words.iter_mut().zip(block.chunks_exact(4)) {
            *word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        let mut working = *state;
        for (index, addition) in Self::ADDITIONS32.into_iter().enumerate() {
            let word = match index < 16 {
                true => words[index],
                false => Self::schedule32(&mut words, index),
            };
            let [a, b, c, d, e, f, g, h] = working;
            let choice = (e & f) ^ (!e & g);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let step = h.wrapping_add(sum1).wrapping_add(choice).wrapping_add(addition).wrapping_add(word);
            working = [step.wrapping_add(sum0).wrapping_add(majority), a, b, c, d.wrapping_add(step), e, f, g];
        }
        for (value, working) in state.iter_mut().zip(working) {
            *value = value.wrapping_add(working);
        }
    }

    /// The message word of step `index`, which the sixteen words before it name.
    pub fn schedule64(words: &mut [u64; 16], index: usize) -> u64 {
        let (previous, recent) = (words[(index + 1) % 16], words[(index + 14) % 16]);
        let low = previous.rotate_right(1) ^ previous.rotate_right(8) ^ (previous >> 7);
        let high = recent.rotate_right(19) ^ recent.rotate_right(61) ^ (recent >> 6);
        words[index % 16] = words[index % 16].wrapping_add(low).wrapping_add(words[(index + 9) % 16]).wrapping_add(high);
        words[index % 16]
    }

    pub fn compress64(state: &mut [u64; 8], block: &[u8; 128]) {
        let mut words = [0u64; 16];
        for (word, chunk) in words.iter_mut().zip(block.chunks_exact(8)) {
            *word = u64::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7]]);
        }
        let mut working = *state;
        for (index, addition) in Self::ADDITIONS64.into_iter().enumerate() {
            let word = match index < 16 {
                true => words[index],
                false => Self::schedule64(&mut words, index),
            };
            let [a, b, c, d, e, f, g, h] = working;
            let choice = (e & f) ^ (!e & g);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let sum1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let sum0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let step = h.wrapping_add(sum1).wrapping_add(choice).wrapping_add(addition).wrapping_add(word);
            working = [step.wrapping_add(sum0).wrapping_add(majority), a, b, c, d.wrapping_add(step), e, f, g];
        }
        for (value, working) in state.iter_mut().zip(working) {
            *value = value.wrapping_add(working);
        }
    }

    pub fn absorb32(state: &mut [u32; 8], buffer: &mut [u8; 64], length: &mut u64, data: &[u8]) {
        let mut filled = (*length % Self::BLOCK_SIZE32 as u64) as usize;
        let mut offset = 0;
        *length = length.wrapping_add(data.len() as u64);
        if filled != 0 {
            offset = (Self::BLOCK_SIZE32 - filled).min(data.len());
            buffer[filled..filled + offset].copy_from_slice(&data[..offset]);
            filled += offset;
            if filled < Self::BLOCK_SIZE32 {
                return;
            }
            Self::compress32(state, buffer);
        }
        let mut data = &data[offset..];
        while let Some((block, rest)) = data.split_first_chunk::<{ Self::BLOCK_SIZE32 }>() {
            Self::compress32(state, block);
            data = rest;
        }
        buffer[..data.len()].copy_from_slice(data);
    }

    pub fn squeeze32(state: &[u32; 8], buffer: &[u8; 64], length: u64) -> [u8; 32] {
        let mut state = *state;
        let filled = (length % Self::BLOCK_SIZE32 as u64) as usize;
        let mut block = [0; Self::BLOCK_SIZE32];
        block[..filled].copy_from_slice(&buffer[..filled]);
        block[filled] = 0x80;
        if filled + 9 > Self::BLOCK_SIZE32 {
            Self::compress32(&mut state, &block);
            block = [0; Self::BLOCK_SIZE32];
        }
        block[Self::BLOCK_SIZE32 - 8..].copy_from_slice(&length.wrapping_mul(8).to_be_bytes());
        Self::compress32(&mut state, &block);
        let mut digest = [0; 32];
        for (chunk, value) in digest.chunks_exact_mut(4).zip(state) {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        digest
    }

    pub fn absorb64(state: &mut [u64; 8], buffer: &mut [u8; 128], length: &mut u128, data: &[u8]) {
        let mut filled = (*length % Self::BLOCK_SIZE64 as u128) as usize;
        let mut offset = 0;
        *length = length.wrapping_add(data.len() as u128);
        if filled != 0 {
            offset = (Self::BLOCK_SIZE64 - filled).min(data.len());
            buffer[filled..filled + offset].copy_from_slice(&data[..offset]);
            filled += offset;
            if filled < Self::BLOCK_SIZE64 {
                return;
            }
            Self::compress64(state, buffer);
        }
        let mut data = &data[offset..];
        while let Some((block, rest)) = data.split_first_chunk::<{ Self::BLOCK_SIZE64 }>() {
            Self::compress64(state, block);
            data = rest;
        }
        buffer[..data.len()].copy_from_slice(data);
    }

    pub fn squeeze64(state: &[u64; 8], buffer: &[u8; 128], length: u128) -> [u8; 64] {
        let mut state = *state;
        let filled = (length % Self::BLOCK_SIZE64 as u128) as usize;
        let mut block = [0; Self::BLOCK_SIZE64];
        block[..filled].copy_from_slice(&buffer[..filled]);
        block[filled] = 0x80;
        if filled + 17 > Self::BLOCK_SIZE64 {
            Self::compress64(&mut state, &block);
            block = [0; Self::BLOCK_SIZE64];
        }
        block[Self::BLOCK_SIZE64 - 16..].copy_from_slice(&length.wrapping_mul(8).to_be_bytes());
        Self::compress64(&mut state, &block);
        let mut digest = [0; 64];
        for (chunk, value) in digest.chunks_exact_mut(8).zip(state) {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        digest
    }
}

impl fmt::Display for SHA2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug)]
pub struct SHA2_224 {
    state: [u32; 8],
    buffer: [u8; 64],
    length: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA2_224 {
    pub const NAME: &'static str = "SHA-224";
    pub const DIGEST_SIZE: usize = 28;
    pub const BLOCK_SIZE: usize = 64;
    pub const INITIAL: [u32; 8] = [
        0xC105_9ED8, 0x367C_D507, 0x3070_DD17, 0xF70E_5939,
        0xFFC0_0B31, 0x6858_1511, 0x64F9_8FA7, 0xBEFA_4FA4,
    ];

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { state: [0; 8], buffer: [0; 64], length: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { state: Self::INITIAL, buffer: [0; 64], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        SHA2::compress32(state, block);
    }

    pub fn absorb(state: &mut [u32; 8], buffer: &mut [u8; 64], length: &mut u64, data: &[u8]) {
        SHA2::absorb32(state, buffer, length, data);
    }

    pub fn squeeze(state: &[u32; 8], buffer: &[u8; 64], length: u64) -> [u8; 28] {
        let mut digest = [0; 28];
        digest.copy_from_slice(&SHA2::squeeze32(state, buffer, length)[..28]);
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
            ProviderBackend::Builtin => (self.state, self.buffer, self.length) = (Self::INITIAL, [0; 64], 0),
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

impl Clone for SHA2_224 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA2_224 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SHA2_256 {
    state: [u32; 8],
    buffer: [u8; 64],
    length: u64,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA2_256 {
    pub const NAME: &'static str = "SHA-256";
    pub const DIGEST_SIZE: usize = 32;
    pub const BLOCK_SIZE: usize = 64;
    pub const INITIAL: [u32; 8] = [
        0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
        0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
    ];

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { state: [0; 8], buffer: [0; 64], length: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { state: Self::INITIAL, buffer: [0; 64], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
        SHA2::compress32(state, block);
    }

    pub fn absorb(state: &mut [u32; 8], buffer: &mut [u8; 64], length: &mut u64, data: &[u8]) {
        SHA2::absorb32(state, buffer, length, data);
    }

    pub fn squeeze(state: &[u32; 8], buffer: &[u8; 64], length: u64) -> [u8; 32] {
        let mut digest = [0; 32];
        digest.copy_from_slice(&SHA2::squeeze32(state, buffer, length)[..32]);
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
            ProviderBackend::Builtin => (self.state, self.buffer, self.length) = (Self::INITIAL, [0; 64], 0),
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

impl Clone for SHA2_256 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA2_256 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SHA2_384 {
    state: [u64; 8],
    buffer: [u8; 128],
    length: u128,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA2_384 {
    pub const NAME: &'static str = "SHA-384";
    pub const DIGEST_SIZE: usize = 48;
    pub const BLOCK_SIZE: usize = 128;
    pub const INITIAL: [u64; 8] = [
        0xCBBB_9D5D_C105_9ED8, 0x629A_292A_367C_D507,
        0x9159_015A_3070_DD17, 0x152F_ECD8_F70E_5939,
        0x6733_2667_FFC0_0B31, 0x8EB4_4A87_6858_1511,
        0xDB0C_2E0D_64F9_8FA7, 0x47B5_481D_BEFA_4FA4,
    ];

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { state: [0; 8], buffer: [0; 128], length: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { state: Self::INITIAL, buffer: [0; 128], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn compress(state: &mut [u64; 8], block: &[u8; 128]) {
        SHA2::compress64(state, block);
    }

    pub fn absorb(state: &mut [u64; 8], buffer: &mut [u8; 128], length: &mut u128, data: &[u8]) {
        SHA2::absorb64(state, buffer, length, data);
    }

    pub fn squeeze(state: &[u64; 8], buffer: &[u8; 128], length: u128) -> [u8; 48] {
        let mut digest = [0; 48];
        digest.copy_from_slice(&SHA2::squeeze64(state, buffer, length)[..48]);
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
            ProviderBackend::Builtin => (self.state, self.buffer, self.length) = (Self::INITIAL, [0; 128], 0),
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

impl Clone for SHA2_384 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA2_384 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SHA2_512 {
    state: [u64; 8],
    buffer: [u8; 128],
    length: u128,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA2_512 {
    pub const NAME: &'static str = "SHA-512";
    pub const DIGEST_SIZE: usize = 64;
    pub const BLOCK_SIZE: usize = 128;
    pub const INITIAL: [u64; 8] = [
        0x6A09_E667_F3BC_C908, 0xBB67_AE85_84CA_A73B,
        0x3C6E_F372_FE94_F82B, 0xA54F_F53A_5F1D_36F1,
        0x510E_527F_ADE6_82D1, 0x9B05_688C_2B3E_6C1F,
        0x1F83_D9AB_FB41_BD6B, 0x5BE0_CD19_137E_2179,
    ];

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { state: [0; 8], buffer: [0; 128], length: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { state: Self::INITIAL, buffer: [0; 128], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn compress(state: &mut [u64; 8], block: &[u8; 128]) {
        SHA2::compress64(state, block);
    }

    pub fn absorb(state: &mut [u64; 8], buffer: &mut [u8; 128], length: &mut u128, data: &[u8]) {
        SHA2::absorb64(state, buffer, length, data);
    }

    pub fn squeeze(state: &[u64; 8], buffer: &[u8; 128], length: u128) -> [u8; 64] {
        let mut digest = [0; 64];
        digest.copy_from_slice(&SHA2::squeeze64(state, buffer, length)[..64]);
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
            ProviderBackend::Builtin => (self.state, self.buffer, self.length) = (Self::INITIAL, [0; 128], 0),
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

impl Clone for SHA2_512 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA2_512 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SHA2_512_224 {
    state: [u64; 8],
    buffer: [u8; 128],
    length: u128,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA2_512_224 {
    pub const NAME: &'static str = "SHA-512/224";
    pub const DIGEST_SIZE: usize = 28;
    pub const BLOCK_SIZE: usize = 128;
    pub const INITIAL: [u64; 8] = [
        0x8C3D_37C8_1954_4DA2, 0x73E1_9966_89DC_D4D6,
        0x1DFA_B7AE_32FF_9C82, 0x679D_D514_582F_9FCF,
        0x0F6D_2B69_7BD4_4DA8, 0x77E3_6F73_04C4_8942,
        0x3F9D_85A8_6A1D_36C8, 0x1112_E6AD_91D6_92A1,
    ];

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { state: [0; 8], buffer: [0; 128], length: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { state: Self::INITIAL, buffer: [0; 128], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn compress(state: &mut [u64; 8], block: &[u8; 128]) {
        SHA2::compress64(state, block);
    }

    pub fn absorb(state: &mut [u64; 8], buffer: &mut [u8; 128], length: &mut u128, data: &[u8]) {
        SHA2::absorb64(state, buffer, length, data);
    }

    pub fn squeeze(state: &[u64; 8], buffer: &[u8; 128], length: u128) -> [u8; 28] {
        let mut digest = [0; 28];
        digest.copy_from_slice(&SHA2::squeeze64(state, buffer, length)[..28]);
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
            ProviderBackend::Builtin => (self.state, self.buffer, self.length) = (Self::INITIAL, [0; 128], 0),
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

impl Clone for SHA2_512_224 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA2_512_224 {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct SHA2_512_256 {
    state: [u64; 8],
    buffer: [u8; 128],
    length: u128,
    backend: ProviderBackend<dyn HashProvider>,
}

impl SHA2_512_256 {
    pub const NAME: &'static str = "SHA-512/256";
    pub const DIGEST_SIZE: usize = 32;
    pub const BLOCK_SIZE: usize = 128;
    pub const INITIAL: [u64; 8] = [
        0x2231_2194_FC2B_F72C, 0x9F55_5FA3_C84C_64C2,
        0x2393_B86B_6F53_B151, 0x9638_7719_5940_EABD,
        0x9628_3EE2_A88E_FFE3, 0xBE5E_1E25_5386_3992,
        0x2B01_99FC_2C85_B8AA, 0x0EB7_2DDC_81C5_2CA2,
    ];

    pub fn new() -> Self {
        match HashProviders::backend(&Self::request()) {
            ProviderBackend::Builtin => Self::builtin(),
            backend => Self { state: [0; 8], buffer: [0; 128], length: 0, backend },
        }
    }

    pub fn builtin() -> Self {
        Self { state: Self::INITIAL, buffer: [0; 128], length: 0, backend: ProviderBackend::Builtin }
    }

    pub fn request() -> HashProviderRequest<'static> {
        HashProviderRequest::new(Self::NAME)
    }

    pub fn compress(state: &mut [u64; 8], block: &[u8; 128]) {
        SHA2::compress64(state, block);
    }

    pub fn absorb(state: &mut [u64; 8], buffer: &mut [u8; 128], length: &mut u128, data: &[u8]) {
        SHA2::absorb64(state, buffer, length, data);
    }

    pub fn squeeze(state: &[u64; 8], buffer: &[u8; 128], length: u128) -> [u8; 32] {
        let mut digest = [0; 32];
        digest.copy_from_slice(&SHA2::squeeze64(state, buffer, length)[..32]);
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
            ProviderBackend::Builtin => (self.state, self.buffer, self.length) = (Self::INITIAL, [0; 128], 0),
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

impl Clone for SHA2_512_256 {
    fn clone(&self) -> Self {
        Self { state: self.state, buffer: self.buffer, length: self.length, backend: self.backend.duplicate(|provider, handle| provider.duplicate(handle)) }
    }
}

impl Default for SHA2_512_256 {
    fn default() -> Self {
        Self::new()
    }
}
