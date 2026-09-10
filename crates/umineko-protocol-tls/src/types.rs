use alloc::{string::String, vec::Vec};
use core::fmt;

use umineko_crypto_hmac::HMACHash;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TLSVersion {
    V1_0,
    V1_1,
    V1_2,
    V1_3,
}

impl TLSVersion {
    pub fn number(&self) -> u16 {
        match self {
            Self::V1_0 => 0x0301,
            Self::V1_1 => 0x0302,
            Self::V1_2 => 0x0303,
            Self::V1_3 => 0x0304,
        }
    }

    pub fn from_number(number: u16) -> Option<Self> {
        match number {
            0x0301 => Some(Self::V1_0),
            0x0302 => Some(Self::V1_1),
            0x0303 => Some(Self::V1_2),
            0x0304 => Some(Self::V1_3),
            _ => None,
        }
    }

    pub fn secure(&self) -> bool {
        matches!(self, Self::V1_2 | Self::V1_3)
    }

    pub fn negotiated_by_extension(&self) -> bool {
        matches!(self, Self::V1_3)
    }

    pub fn early_data(&self) -> bool {
        matches!(self, Self::V1_3)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V1_0 => "TLSv1.0",
            Self::V1_1 => "TLSv1.1",
            Self::V1_2 => "TLSv1.2",
            Self::V1_3 => "TLSv1.3",
        }
    }
}

impl fmt::Display for TLSVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSRole {
    Client,
    Server,
}

impl TLSRole {
    pub fn peer(&self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSRecommendation {
    Recommended,
    NotRecommended,
    Discouraged,
}

impl TLSRecommendation {
    pub const ALL: [Self; 3] = [Self::Recommended, Self::NotRecommended, Self::Discouraged];

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Recommended => "Y",
            Self::NotRecommended => "N",
            Self::Discouraged => "D",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|value| value.as_str() == name)
    }
}

impl fmt::Display for TLSRecommendation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSGroupKind {
    EllipticCurve,
    FiniteField,
    KeyEncapsulation,
    Hybrid,
    Explicit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TLSGroupSpecification {
    pub number: u16,
    pub name: &'static str,
    pub kind: TLSGroupKind,
    pub versions: &'static [TLSVersion],
    pub datagram: bool,
    pub recommendation: TLSRecommendation,
    pub client_share_size: Option<usize>,
    pub server_share_size: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSGroup {
    SECT163K1,
    SECT163R1,
    SECT163R2,
    SECT193R1,
    SECT193R2,
    SECT233K1,
    SECT233R1,
    SECT239K1,
    SECT283K1,
    SECT283R1,
    SECT409K1,
    SECT409R1,
    SECT571K1,
    SECT571R1,
    SECP160K1,
    SECP160R1,
    SECP160R2,
    SECP192K1,
    SECP192R1,
    SECP224K1,
    SECP224R1,
    SECP256K1,
    SECP256R1,
    SECP384R1,
    SECP521R1,
    BRAINPOOLP256R1,
    BRAINPOOLP384R1,
    BRAINPOOLP512R1,
    X25519,
    X448,
    BRAINPOOLP256R1TLS13,
    BRAINPOOLP384R1TLS13,
    BRAINPOOLP512R1TLS13,
    GC256A,
    GC256B,
    GC256C,
    GC256D,
    GC512A,
    GC512B,
    GC512C,
    CURVESM2,
    FFDHE2048,
    FFDHE3072,
    FFDHE4096,
    FFDHE6144,
    FFDHE8192,
    MLKEM512,
    MLKEM768,
    MLKEM1024,
    SECP256R1MLKEM512,
    MLKEM512X25519,
    SECP256R1MLKEM768,
    X25519MLKEM768,
    SECP384R1MLKEM1024,
    CURVESM2MLKEM768,
    ARBITRARY_EXPLICIT_PRIME_CURVES,
    ARBITRARY_EXPLICIT_CHAR2_CURVES,
}

impl TLSGroup {
    pub const ALL: [Self; 57] = [
        Self::SECT163K1,
        Self::SECT163R1,
        Self::SECT163R2,
        Self::SECT193R1,
        Self::SECT193R2,
        Self::SECT233K1,
        Self::SECT233R1,
        Self::SECT239K1,
        Self::SECT283K1,
        Self::SECT283R1,
        Self::SECT409K1,
        Self::SECT409R1,
        Self::SECT571K1,
        Self::SECT571R1,
        Self::SECP160K1,
        Self::SECP160R1,
        Self::SECP160R2,
        Self::SECP192K1,
        Self::SECP192R1,
        Self::SECP224K1,
        Self::SECP224R1,
        Self::SECP256K1,
        Self::SECP256R1,
        Self::SECP384R1,
        Self::SECP521R1,
        Self::BRAINPOOLP256R1,
        Self::BRAINPOOLP384R1,
        Self::BRAINPOOLP512R1,
        Self::X25519,
        Self::X448,
        Self::BRAINPOOLP256R1TLS13,
        Self::BRAINPOOLP384R1TLS13,
        Self::BRAINPOOLP512R1TLS13,
        Self::GC256A,
        Self::GC256B,
        Self::GC256C,
        Self::GC256D,
        Self::GC512A,
        Self::GC512B,
        Self::GC512C,
        Self::CURVESM2,
        Self::FFDHE2048,
        Self::FFDHE3072,
        Self::FFDHE4096,
        Self::FFDHE6144,
        Self::FFDHE8192,
        Self::MLKEM512,
        Self::MLKEM768,
        Self::MLKEM1024,
        Self::SECP256R1MLKEM512,
        Self::MLKEM512X25519,
        Self::SECP256R1MLKEM768,
        Self::X25519MLKEM768,
        Self::SECP384R1MLKEM1024,
        Self::CURVESM2MLKEM768,
        Self::ARBITRARY_EXPLICIT_PRIME_CURVES,
        Self::ARBITRARY_EXPLICIT_CHAR2_CURVES,
    ];

    pub fn specification(&self) -> TLSGroupSpecification {
        match self {
            Self::SECT163K1 => TLSGroupSpecification { number: 1, name: "sect163k1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::Discouraged, client_share_size: Some(43), server_share_size: Some(43) },
            Self::SECT163R1 => TLSGroupSpecification { number: 2, name: "sect163r1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::Discouraged, client_share_size: Some(43), server_share_size: Some(43) },
            Self::SECT163R2 => TLSGroupSpecification { number: 3, name: "sect163r2", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::Discouraged, client_share_size: Some(43), server_share_size: Some(43) },
            Self::SECT193R1 => TLSGroupSpecification { number: 4, name: "sect193r1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::Discouraged, client_share_size: Some(51), server_share_size: Some(51) },
            Self::SECT193R2 => TLSGroupSpecification { number: 5, name: "sect193r2", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::Discouraged, client_share_size: Some(51), server_share_size: Some(51) },
            Self::SECT233K1 => TLSGroupSpecification { number: 6, name: "sect233k1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::Discouraged, client_share_size: Some(61), server_share_size: Some(61) },
            Self::SECT233R1 => TLSGroupSpecification { number: 7, name: "sect233r1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::Discouraged, client_share_size: Some(61), server_share_size: Some(61) },
            Self::SECT239K1 => TLSGroupSpecification { number: 8, name: "sect239k1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::Discouraged, client_share_size: Some(61), server_share_size: Some(61) },
            Self::SECT283K1 => TLSGroupSpecification { number: 9, name: "sect283k1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(73), server_share_size: Some(73) },
            Self::SECT283R1 => TLSGroupSpecification { number: 10, name: "sect283r1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(73), server_share_size: Some(73) },
            Self::SECT409K1 => TLSGroupSpecification { number: 11, name: "sect409k1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(105), server_share_size: Some(105) },
            Self::SECT409R1 => TLSGroupSpecification { number: 12, name: "sect409r1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(105), server_share_size: Some(105) },
            Self::SECT571K1 => TLSGroupSpecification { number: 13, name: "sect571k1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(145), server_share_size: Some(145) },
            Self::SECT571R1 => TLSGroupSpecification { number: 14, name: "sect571r1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(145), server_share_size: Some(145) },
            Self::SECP160K1 => TLSGroupSpecification { number: 15, name: "secp160k1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::Discouraged, client_share_size: Some(41), server_share_size: Some(41) },
            Self::SECP160R1 => TLSGroupSpecification { number: 16, name: "secp160r1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::Discouraged, client_share_size: Some(41), server_share_size: Some(41) },
            Self::SECP160R2 => TLSGroupSpecification { number: 17, name: "secp160r2", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::Discouraged, client_share_size: Some(41), server_share_size: Some(41) },
            Self::SECP192K1 => TLSGroupSpecification { number: 18, name: "secp192k1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::Discouraged, client_share_size: Some(49), server_share_size: Some(49) },
            Self::SECP192R1 => TLSGroupSpecification { number: 19, name: "secp192r1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::Discouraged, client_share_size: Some(49), server_share_size: Some(49) },
            Self::SECP224K1 => TLSGroupSpecification { number: 20, name: "secp224k1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::Discouraged, client_share_size: Some(57), server_share_size: Some(57) },
            Self::SECP224R1 => TLSGroupSpecification { number: 21, name: "secp224r1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::Discouraged, client_share_size: Some(57), server_share_size: Some(57) },
            Self::SECP256K1 => TLSGroupSpecification { number: 22, name: "secp256k1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(65), server_share_size: Some(65) },
            Self::SECP256R1 => TLSGroupSpecification { number: 23, name: "secp256r1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2, TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::Recommended, client_share_size: Some(65), server_share_size: Some(65) },
            Self::SECP384R1 => TLSGroupSpecification { number: 24, name: "secp384r1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2, TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::Recommended, client_share_size: Some(97), server_share_size: Some(97) },
            Self::SECP521R1 => TLSGroupSpecification { number: 25, name: "secp521r1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2, TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(133), server_share_size: Some(133) },
            Self::BRAINPOOLP256R1 => TLSGroupSpecification { number: 26, name: "brainpoolP256r1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(65), server_share_size: Some(65) },
            Self::BRAINPOOLP384R1 => TLSGroupSpecification { number: 27, name: "brainpoolP384r1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(97), server_share_size: Some(97) },
            Self::BRAINPOOLP512R1 => TLSGroupSpecification { number: 28, name: "brainpoolP512r1", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(129), server_share_size: Some(129) },
            Self::X25519 => TLSGroupSpecification { number: 29, name: "x25519", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2, TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::Recommended, client_share_size: Some(32), server_share_size: Some(32) },
            Self::X448 => TLSGroupSpecification { number: 30, name: "x448", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2, TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::Recommended, client_share_size: Some(56), server_share_size: Some(56) },
            Self::BRAINPOOLP256R1TLS13 => TLSGroupSpecification { number: 31, name: "brainpoolP256r1tls13", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(65), server_share_size: Some(65) },
            Self::BRAINPOOLP384R1TLS13 => TLSGroupSpecification { number: 32, name: "brainpoolP384r1tls13", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(97), server_share_size: Some(97) },
            Self::BRAINPOOLP512R1TLS13 => TLSGroupSpecification { number: 33, name: "brainpoolP512r1tls13", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(129), server_share_size: Some(129) },
            Self::GC256A => TLSGroupSpecification { number: 34, name: "GC256A", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_2, TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(64), server_share_size: Some(64) },
            Self::GC256B => TLSGroupSpecification { number: 35, name: "GC256B", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_2, TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(64), server_share_size: Some(64) },
            Self::GC256C => TLSGroupSpecification { number: 36, name: "GC256C", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_2, TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(64), server_share_size: Some(64) },
            Self::GC256D => TLSGroupSpecification { number: 37, name: "GC256D", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_2, TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(64), server_share_size: Some(64) },
            Self::GC512A => TLSGroupSpecification { number: 38, name: "GC512A", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_2, TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(128), server_share_size: Some(128) },
            Self::GC512B => TLSGroupSpecification { number: 39, name: "GC512B", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_2, TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(128), server_share_size: Some(128) },
            Self::GC512C => TLSGroupSpecification { number: 40, name: "GC512C", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_2, TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(128), server_share_size: Some(128) },
            Self::CURVESM2 => TLSGroupSpecification { number: 41, name: "curveSM2", kind: TLSGroupKind::EllipticCurve, versions: &[TLSVersion::V1_3], datagram: false, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(65), server_share_size: Some(65) },
            Self::FFDHE2048 => TLSGroupSpecification { number: 256, name: "ffdhe2048", kind: TLSGroupKind::FiniteField, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2, TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(256), server_share_size: Some(256) },
            Self::FFDHE3072 => TLSGroupSpecification { number: 257, name: "ffdhe3072", kind: TLSGroupKind::FiniteField, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2, TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(384), server_share_size: Some(384) },
            Self::FFDHE4096 => TLSGroupSpecification { number: 258, name: "ffdhe4096", kind: TLSGroupKind::FiniteField, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2, TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(512), server_share_size: Some(512) },
            Self::FFDHE6144 => TLSGroupSpecification { number: 259, name: "ffdhe6144", kind: TLSGroupKind::FiniteField, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2, TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(768), server_share_size: Some(768) },
            Self::FFDHE8192 => TLSGroupSpecification { number: 260, name: "ffdhe8192", kind: TLSGroupKind::FiniteField, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2, TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(1024), server_share_size: Some(1024) },
            Self::MLKEM512 => TLSGroupSpecification { number: 512, name: "MLKEM512", kind: TLSGroupKind::KeyEncapsulation, versions: &[TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(800), server_share_size: Some(768) },
            Self::MLKEM768 => TLSGroupSpecification { number: 513, name: "MLKEM768", kind: TLSGroupKind::KeyEncapsulation, versions: &[TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(1184), server_share_size: Some(1088) },
            Self::MLKEM1024 => TLSGroupSpecification { number: 514, name: "MLKEM1024", kind: TLSGroupKind::KeyEncapsulation, versions: &[TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(1568), server_share_size: Some(1568) },
            Self::SECP256R1MLKEM512 => TLSGroupSpecification { number: 4585, name: "SecP256r1MLKEM512", kind: TLSGroupKind::Hybrid, versions: &[TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(865), server_share_size: Some(833) },
            Self::MLKEM512X25519 => TLSGroupSpecification { number: 4586, name: "MLKEM512X25519", kind: TLSGroupKind::Hybrid, versions: &[TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(832), server_share_size: Some(800) },
            Self::SECP256R1MLKEM768 => TLSGroupSpecification { number: 4587, name: "SecP256r1MLKEM768", kind: TLSGroupKind::Hybrid, versions: &[TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(1249), server_share_size: Some(1153) },
            Self::X25519MLKEM768 => TLSGroupSpecification { number: 4588, name: "X25519MLKEM768", kind: TLSGroupKind::Hybrid, versions: &[TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::Recommended, client_share_size: Some(1216), server_share_size: Some(1120) },
            Self::SECP384R1MLKEM1024 => TLSGroupSpecification { number: 4589, name: "SecP384r1MLKEM1024", kind: TLSGroupKind::Hybrid, versions: &[TLSVersion::V1_3], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(1665), server_share_size: Some(1665) },
            Self::CURVESM2MLKEM768 => TLSGroupSpecification { number: 4590, name: "curveSM2MLKEM768", kind: TLSGroupKind::Hybrid, versions: &[TLSVersion::V1_3], datagram: false, recommendation: TLSRecommendation::NotRecommended, client_share_size: Some(1249), server_share_size: Some(1153) },
            Self::ARBITRARY_EXPLICIT_PRIME_CURVES => TLSGroupSpecification { number: 65281, name: "arbitrary_explicit_prime_curves", kind: TLSGroupKind::Explicit, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: None, server_share_size: None },
            Self::ARBITRARY_EXPLICIT_CHAR2_CURVES => TLSGroupSpecification { number: 65282, name: "arbitrary_explicit_char2_curves", kind: TLSGroupKind::Explicit, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], datagram: true, recommendation: TLSRecommendation::NotRecommended, client_share_size: None, server_share_size: None },
        }
    }

    pub fn number(&self) -> u16 {
        self.specification().number
    }

    pub fn from_number(number: u16) -> Option<Self> {
        Self::ALL.iter().copied().find(|group| group.number() == number)
    }

    pub fn kind(&self) -> TLSGroupKind {
        self.specification().kind
    }

    pub fn post_quantum(&self) -> bool {
        matches!(self.kind(), TLSGroupKind::KeyEncapsulation | TLSGroupKind::Hybrid)
    }

    pub fn hybrid(&self) -> bool {
        matches!(self.kind(), TLSGroupKind::Hybrid)
    }

    pub fn versions(&self) -> &'static [TLSVersion] {
        self.specification().versions
    }

    pub fn datagram(&self) -> bool {
        self.specification().datagram
    }

    pub fn recommendation(&self) -> TLSRecommendation {
        self.specification().recommendation
    }

    pub fn share_size(&self, role: TLSRole) -> Option<usize> {
        match role {
            TLSRole::Client => self.specification().client_share_size,
            TLSRole::Server => self.specification().server_share_size,
        }
    }

    pub fn as_str(&self) -> &'static str {
        self.specification().name
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|group| group.as_str() == name)
    }
}

impl fmt::Display for TLSGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSECPointFormat {
    UNCOMPRESSED,
    ANSIX962_COMPRESSED_PRIME,
    ANSIX962_COMPRESSED_CHAR2,
}

impl TLSECPointFormat {
    pub const ALL: [Self; 3] = [Self::UNCOMPRESSED, Self::ANSIX962_COMPRESSED_PRIME, Self::ANSIX962_COMPRESSED_CHAR2];

    pub fn number(&self) -> u8 {
        match self {
            Self::UNCOMPRESSED => 0,
            Self::ANSIX962_COMPRESSED_PRIME => 1,
            Self::ANSIX962_COMPRESSED_CHAR2 => 2,
        }
    }

    pub fn from_number(number: u8) -> Option<Self> {
        Self::ALL.iter().copied().find(|format| format.number() == number)
    }

    pub fn datagram(&self) -> bool {
        match self {
            Self::UNCOMPRESSED | Self::ANSIX962_COMPRESSED_PRIME | Self::ANSIX962_COMPRESSED_CHAR2 => true,
        }
    }

    pub fn deprecated(&self) -> bool {
        match self {
            Self::UNCOMPRESSED => false,
            Self::ANSIX962_COMPRESSED_PRIME | Self::ANSIX962_COMPRESSED_CHAR2 => true,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UNCOMPRESSED => "uncompressed",
            Self::ANSIX962_COMPRESSED_PRIME => "ansiX962_compressed_prime",
            Self::ANSIX962_COMPRESSED_CHAR2 => "ansiX962_compressed_char2",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|format| format.as_str() == name)
    }
}

impl fmt::Display for TLSECPointFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSECCurveType {
    EXPLICIT_PRIME,
    EXPLICIT_CHAR2,
    NAMED_CURVE,
}

impl TLSECCurveType {
    pub const ALL: [Self; 3] = [Self::EXPLICIT_PRIME, Self::EXPLICIT_CHAR2, Self::NAMED_CURVE];

    pub fn number(&self) -> u8 {
        match self {
            Self::EXPLICIT_PRIME => 1,
            Self::EXPLICIT_CHAR2 => 2,
            Self::NAMED_CURVE => 3,
        }
    }

    pub fn from_number(number: u8) -> Option<Self> {
        Self::ALL.iter().copied().find(|curve_type| curve_type.number() == number)
    }

    pub fn datagram(&self) -> bool {
        match self {
            Self::EXPLICIT_PRIME | Self::EXPLICIT_CHAR2 | Self::NAMED_CURVE => true,
        }
    }

    pub fn deprecated(&self) -> bool {
        match self {
            Self::EXPLICIT_PRIME | Self::EXPLICIT_CHAR2 => true,
            Self::NAMED_CURVE => false,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EXPLICIT_PRIME => "explicit_prime",
            Self::EXPLICIT_CHAR2 => "explicit_char2",
            Self::NAMED_CURVE => "named_curve",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|curve_type| curve_type.as_str() == name)
    }
}

impl fmt::Display for TLSECCurveType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSKeyExchange {
    RSA,
    DH_DSS,
    DH_RSA,
    DHE_DSS,
    DHE_RSA,
    DH_anon,
    KRB5,
    PSK,
    DHE_PSK,
    RSA_PSK,
    ECDH_ECDSA,
    ECDHE_ECDSA,
    ECDH_RSA,
    ECDHE_RSA,
    ECDH_anon,
    SRP_SHA,
    SRP_SHA_RSA,
    SRP_SHA_DSS,
    ECDHE_PSK,
    ECCPWD,
    GOSTR341112_256,
}

impl TLSKeyExchange {
    pub const ALL: [Self; 21] = [Self::RSA, Self::DH_DSS, Self::DH_RSA, Self::DHE_DSS, Self::DHE_RSA, Self::DH_anon, Self::KRB5, Self::PSK, Self::DHE_PSK, Self::RSA_PSK, Self::ECDH_ECDSA, Self::ECDHE_ECDSA, Self::ECDH_RSA, Self::ECDHE_RSA, Self::ECDH_anon, Self::SRP_SHA, Self::SRP_SHA_RSA, Self::SRP_SHA_DSS, Self::ECDHE_PSK, Self::ECCPWD, Self::GOSTR341112_256];

    pub fn forward_secrecy(&self) -> bool {
        match self {
            Self::RSA => false,
            Self::DH_DSS => false,
            Self::DH_RSA => false,
            Self::DHE_DSS => true,
            Self::DHE_RSA => true,
            Self::DH_anon => true,
            Self::KRB5 => false,
            Self::PSK => false,
            Self::DHE_PSK => true,
            Self::RSA_PSK => false,
            Self::ECDH_ECDSA => false,
            Self::ECDHE_ECDSA => true,
            Self::ECDH_RSA => false,
            Self::ECDHE_RSA => true,
            Self::ECDH_anon => true,
            Self::SRP_SHA => true,
            Self::SRP_SHA_RSA => true,
            Self::SRP_SHA_DSS => true,
            Self::ECDHE_PSK => true,
            Self::ECCPWD => true,
            Self::GOSTR341112_256 => false,
        }
    }

    pub fn anonymous(&self) -> bool {
        match self {
            Self::RSA => false,
            Self::DH_DSS => false,
            Self::DH_RSA => false,
            Self::DHE_DSS => false,
            Self::DHE_RSA => false,
            Self::DH_anon => true,
            Self::KRB5 => false,
            Self::PSK => false,
            Self::DHE_PSK => false,
            Self::RSA_PSK => false,
            Self::ECDH_ECDSA => false,
            Self::ECDHE_ECDSA => false,
            Self::ECDH_RSA => false,
            Self::ECDHE_RSA => false,
            Self::ECDH_anon => true,
            Self::SRP_SHA => false,
            Self::SRP_SHA_RSA => false,
            Self::SRP_SHA_DSS => false,
            Self::ECDHE_PSK => false,
            Self::ECCPWD => false,
            Self::GOSTR341112_256 => false,
        }
    }

    pub fn psk(&self) -> bool {
        match self {
            Self::RSA => false,
            Self::DH_DSS => false,
            Self::DH_RSA => false,
            Self::DHE_DSS => false,
            Self::DHE_RSA => false,
            Self::DH_anon => false,
            Self::KRB5 => false,
            Self::PSK => true,
            Self::DHE_PSK => true,
            Self::RSA_PSK => true,
            Self::ECDH_ECDSA => false,
            Self::ECDHE_ECDSA => false,
            Self::ECDH_RSA => false,
            Self::ECDHE_RSA => false,
            Self::ECDH_anon => false,
            Self::SRP_SHA => false,
            Self::SRP_SHA_RSA => false,
            Self::SRP_SHA_DSS => false,
            Self::ECDHE_PSK => true,
            Self::ECCPWD => false,
            Self::GOSTR341112_256 => false,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RSA => "RSA",
            Self::DH_DSS => "DH_DSS",
            Self::DH_RSA => "DH_RSA",
            Self::DHE_DSS => "DHE_DSS",
            Self::DHE_RSA => "DHE_RSA",
            Self::DH_anon => "DH_anon",
            Self::KRB5 => "KRB5",
            Self::PSK => "PSK",
            Self::DHE_PSK => "DHE_PSK",
            Self::RSA_PSK => "RSA_PSK",
            Self::ECDH_ECDSA => "ECDH_ECDSA",
            Self::ECDHE_ECDSA => "ECDHE_ECDSA",
            Self::ECDH_RSA => "ECDH_RSA",
            Self::ECDHE_RSA => "ECDHE_RSA",
            Self::ECDH_anon => "ECDH_anon",
            Self::SRP_SHA => "SRP_SHA",
            Self::SRP_SHA_RSA => "SRP_SHA_RSA",
            Self::SRP_SHA_DSS => "SRP_SHA_DSS",
            Self::ECDHE_PSK => "ECDHE_PSK",
            Self::ECCPWD => "ECCPWD",
            Self::GOSTR341112_256 => "GOSTR341112_256",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|value| value.as_str() == name)
    }
}

impl fmt::Display for TLSKeyExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSEncryption {
    NULL,
    RC4_40,
    RC4_128,
    RC2_CBC_40,
    DES40_CBC,
    DES_CBC,
    IDEA_CBC,
    TRIPLEDES_EDE_CBC,
    AES_128_CBC,
    AES_256_CBC,
    AES_128_GCM,
    AES_256_GCM,
    AES_128_CCM,
    AES_256_CCM,
    AES_128_CCM_8,
    AES_256_CCM_8,
    CAMELLIA_128_CBC,
    CAMELLIA_256_CBC,
    CAMELLIA_128_GCM,
    CAMELLIA_256_GCM,
    ARIA_128_CBC,
    ARIA_256_CBC,
    ARIA_128_GCM,
    ARIA_256_GCM,
    SEED_CBC,
    CHACHA20_POLY1305,
    SM4_GCM,
    SM4_CCM,
    AEGIS_128L,
    AEGIS_256,
    ASCONAEAD128,
    KUZNYECHIK_CTR_ACPKM,
    MAGMA_CTR_ACPKM,
    GOST28147_CNT,
    KUZNYECHIK_MGM_L,
    KUZNYECHIK_MGM_S,
    MAGMA_MGM_L,
    MAGMA_MGM_S,
}

impl TLSEncryption {
    pub const ALL: [Self; 38] = [Self::NULL, Self::RC4_40, Self::RC4_128, Self::RC2_CBC_40, Self::DES40_CBC, Self::DES_CBC, Self::IDEA_CBC, Self::TRIPLEDES_EDE_CBC, Self::AES_128_CBC, Self::AES_256_CBC, Self::AES_128_GCM, Self::AES_256_GCM, Self::AES_128_CCM, Self::AES_256_CCM, Self::AES_128_CCM_8, Self::AES_256_CCM_8, Self::CAMELLIA_128_CBC, Self::CAMELLIA_256_CBC, Self::CAMELLIA_128_GCM, Self::CAMELLIA_256_GCM, Self::ARIA_128_CBC, Self::ARIA_256_CBC, Self::ARIA_128_GCM, Self::ARIA_256_GCM, Self::SEED_CBC, Self::CHACHA20_POLY1305, Self::SM4_GCM, Self::SM4_CCM, Self::AEGIS_128L, Self::AEGIS_256, Self::ASCONAEAD128, Self::KUZNYECHIK_CTR_ACPKM, Self::MAGMA_CTR_ACPKM, Self::GOST28147_CNT, Self::KUZNYECHIK_MGM_L, Self::KUZNYECHIK_MGM_S, Self::MAGMA_MGM_L, Self::MAGMA_MGM_S];

    pub fn aead(&self) -> bool {
        match self {
            Self::NULL => false,
            Self::RC4_40 => false,
            Self::RC4_128 => false,
            Self::RC2_CBC_40 => false,
            Self::DES40_CBC => false,
            Self::DES_CBC => false,
            Self::IDEA_CBC => false,
            Self::TRIPLEDES_EDE_CBC => false,
            Self::AES_128_CBC => false,
            Self::AES_256_CBC => false,
            Self::AES_128_GCM => true,
            Self::AES_256_GCM => true,
            Self::AES_128_CCM => true,
            Self::AES_256_CCM => true,
            Self::AES_128_CCM_8 => true,
            Self::AES_256_CCM_8 => true,
            Self::CAMELLIA_128_CBC => false,
            Self::CAMELLIA_256_CBC => false,
            Self::CAMELLIA_128_GCM => true,
            Self::CAMELLIA_256_GCM => true,
            Self::ARIA_128_CBC => false,
            Self::ARIA_256_CBC => false,
            Self::ARIA_128_GCM => true,
            Self::ARIA_256_GCM => true,
            Self::SEED_CBC => false,
            Self::CHACHA20_POLY1305 => true,
            Self::SM4_GCM => true,
            Self::SM4_CCM => true,
            Self::AEGIS_128L => true,
            Self::AEGIS_256 => true,
            Self::ASCONAEAD128 => true,
            Self::KUZNYECHIK_CTR_ACPKM => false,
            Self::MAGMA_CTR_ACPKM => false,
            Self::GOST28147_CNT => false,
            Self::KUZNYECHIK_MGM_L => true,
            Self::KUZNYECHIK_MGM_S => true,
            Self::MAGMA_MGM_L => true,
            Self::MAGMA_MGM_S => true,
        }
    }

    pub fn key_size(&self) -> usize {
        match self {
            Self::NULL => 0,
            Self::RC4_40 => 5,
            Self::RC4_128 => 16,
            Self::RC2_CBC_40 => 5,
            Self::DES40_CBC => 5,
            Self::DES_CBC => 8,
            Self::IDEA_CBC => 16,
            Self::TRIPLEDES_EDE_CBC => 24,
            Self::AES_128_CBC => 16,
            Self::AES_256_CBC => 32,
            Self::AES_128_GCM => 16,
            Self::AES_256_GCM => 32,
            Self::AES_128_CCM => 16,
            Self::AES_256_CCM => 32,
            Self::AES_128_CCM_8 => 16,
            Self::AES_256_CCM_8 => 32,
            Self::CAMELLIA_128_CBC => 16,
            Self::CAMELLIA_256_CBC => 32,
            Self::CAMELLIA_128_GCM => 16,
            Self::CAMELLIA_256_GCM => 32,
            Self::ARIA_128_CBC => 16,
            Self::ARIA_256_CBC => 32,
            Self::ARIA_128_GCM => 16,
            Self::ARIA_256_GCM => 32,
            Self::SEED_CBC => 16,
            Self::CHACHA20_POLY1305 => 32,
            Self::SM4_GCM => 16,
            Self::SM4_CCM => 16,
            Self::AEGIS_128L => 16,
            Self::AEGIS_256 => 32,
            Self::ASCONAEAD128 => 16,
            Self::KUZNYECHIK_CTR_ACPKM => 32,
            Self::MAGMA_CTR_ACPKM => 32,
            Self::GOST28147_CNT => 32,
            Self::KUZNYECHIK_MGM_L => 32,
            Self::KUZNYECHIK_MGM_S => 32,
            Self::MAGMA_MGM_L => 32,
            Self::MAGMA_MGM_S => 32,
        }
    }

    pub fn nonce_size(&self) -> usize {
        match self {
            Self::NULL => 0,
            Self::RC4_40 => 0,
            Self::RC4_128 => 0,
            Self::RC2_CBC_40 => 8,
            Self::DES40_CBC => 8,
            Self::DES_CBC => 8,
            Self::IDEA_CBC => 8,
            Self::TRIPLEDES_EDE_CBC => 8,
            Self::AES_128_CBC => 16,
            Self::AES_256_CBC => 16,
            Self::AES_128_GCM => 12,
            Self::AES_256_GCM => 12,
            Self::AES_128_CCM => 12,
            Self::AES_256_CCM => 12,
            Self::AES_128_CCM_8 => 12,
            Self::AES_256_CCM_8 => 12,
            Self::CAMELLIA_128_CBC => 16,
            Self::CAMELLIA_256_CBC => 16,
            Self::CAMELLIA_128_GCM => 12,
            Self::CAMELLIA_256_GCM => 12,
            Self::ARIA_128_CBC => 16,
            Self::ARIA_256_CBC => 16,
            Self::ARIA_128_GCM => 12,
            Self::ARIA_256_GCM => 12,
            Self::SEED_CBC => 16,
            Self::CHACHA20_POLY1305 => 12,
            Self::SM4_GCM => 12,
            Self::SM4_CCM => 12,
            Self::AEGIS_128L => 16,
            Self::AEGIS_256 => 32,
            Self::ASCONAEAD128 => 16,
            Self::KUZNYECHIK_CTR_ACPKM => 8,
            Self::MAGMA_CTR_ACPKM => 4,
            Self::GOST28147_CNT => 8,
            Self::KUZNYECHIK_MGM_L => 16,
            Self::KUZNYECHIK_MGM_S => 16,
            Self::MAGMA_MGM_L => 8,
            Self::MAGMA_MGM_S => 8,
        }
    }

    pub fn tag_size(&self) -> usize {
        match self {
            Self::NULL => 0,
            Self::RC4_40 => 0,
            Self::RC4_128 => 0,
            Self::RC2_CBC_40 => 0,
            Self::DES40_CBC => 0,
            Self::DES_CBC => 0,
            Self::IDEA_CBC => 0,
            Self::TRIPLEDES_EDE_CBC => 0,
            Self::AES_128_CBC => 0,
            Self::AES_256_CBC => 0,
            Self::AES_128_GCM => 16,
            Self::AES_256_GCM => 16,
            Self::AES_128_CCM => 16,
            Self::AES_256_CCM => 16,
            Self::AES_128_CCM_8 => 8,
            Self::AES_256_CCM_8 => 8,
            Self::CAMELLIA_128_CBC => 0,
            Self::CAMELLIA_256_CBC => 0,
            Self::CAMELLIA_128_GCM => 16,
            Self::CAMELLIA_256_GCM => 16,
            Self::ARIA_128_CBC => 0,
            Self::ARIA_256_CBC => 0,
            Self::ARIA_128_GCM => 16,
            Self::ARIA_256_GCM => 16,
            Self::SEED_CBC => 0,
            Self::CHACHA20_POLY1305 => 16,
            Self::SM4_GCM => 16,
            Self::SM4_CCM => 16,
            Self::AEGIS_128L => 16,
            Self::AEGIS_256 => 16,
            Self::ASCONAEAD128 => 16,
            Self::KUZNYECHIK_CTR_ACPKM => 0,
            Self::MAGMA_CTR_ACPKM => 0,
            Self::GOST28147_CNT => 0,
            Self::KUZNYECHIK_MGM_L => 16,
            Self::KUZNYECHIK_MGM_S => 16,
            Self::MAGMA_MGM_L => 8,
            Self::MAGMA_MGM_S => 8,
        }
    }

    pub fn block_size(&self) -> Option<usize> {
        match self {
            Self::NULL => None,
            Self::RC4_40 => None,
            Self::RC4_128 => None,
            Self::RC2_CBC_40 => Some(8),
            Self::DES40_CBC => Some(8),
            Self::DES_CBC => Some(8),
            Self::IDEA_CBC => Some(8),
            Self::TRIPLEDES_EDE_CBC => Some(8),
            Self::AES_128_CBC => Some(16),
            Self::AES_256_CBC => Some(16),
            Self::AES_128_GCM => Some(16),
            Self::AES_256_GCM => Some(16),
            Self::AES_128_CCM => Some(16),
            Self::AES_256_CCM => Some(16),
            Self::AES_128_CCM_8 => Some(16),
            Self::AES_256_CCM_8 => Some(16),
            Self::CAMELLIA_128_CBC => Some(16),
            Self::CAMELLIA_256_CBC => Some(16),
            Self::CAMELLIA_128_GCM => Some(16),
            Self::CAMELLIA_256_GCM => Some(16),
            Self::ARIA_128_CBC => Some(16),
            Self::ARIA_256_CBC => Some(16),
            Self::ARIA_128_GCM => Some(16),
            Self::ARIA_256_GCM => Some(16),
            Self::SEED_CBC => Some(16),
            Self::CHACHA20_POLY1305 => None,
            Self::SM4_GCM => Some(16),
            Self::SM4_CCM => Some(16),
            Self::AEGIS_128L => None,
            Self::AEGIS_256 => None,
            Self::ASCONAEAD128 => None,
            Self::KUZNYECHIK_CTR_ACPKM => Some(16),
            Self::MAGMA_CTR_ACPKM => Some(8),
            Self::GOST28147_CNT => Some(8),
            Self::KUZNYECHIK_MGM_L => Some(16),
            Self::KUZNYECHIK_MGM_S => Some(16),
            Self::MAGMA_MGM_L => Some(8),
            Self::MAGMA_MGM_S => Some(8),
        }
    }

    pub fn section_size(&self) -> Option<usize> {
        match self {
            Self::NULL => None,
            Self::RC4_40 => None,
            Self::RC4_128 => None,
            Self::RC2_CBC_40 => None,
            Self::DES40_CBC => None,
            Self::DES_CBC => None,
            Self::IDEA_CBC => None,
            Self::TRIPLEDES_EDE_CBC => None,
            Self::AES_128_CBC => None,
            Self::AES_256_CBC => None,
            Self::AES_128_GCM => None,
            Self::AES_256_GCM => None,
            Self::AES_128_CCM => None,
            Self::AES_256_CCM => None,
            Self::AES_128_CCM_8 => None,
            Self::AES_256_CCM_8 => None,
            Self::CAMELLIA_128_CBC => None,
            Self::CAMELLIA_256_CBC => None,
            Self::CAMELLIA_128_GCM => None,
            Self::CAMELLIA_256_GCM => None,
            Self::ARIA_128_CBC => None,
            Self::ARIA_256_CBC => None,
            Self::ARIA_128_GCM => None,
            Self::ARIA_256_GCM => None,
            Self::SEED_CBC => None,
            Self::CHACHA20_POLY1305 => None,
            Self::SM4_GCM => None,
            Self::SM4_CCM => None,
            Self::AEGIS_128L => None,
            Self::AEGIS_256 => None,
            Self::ASCONAEAD128 => None,
            Self::KUZNYECHIK_CTR_ACPKM => Some(4096),
            Self::MAGMA_CTR_ACPKM => Some(1024),
            Self::GOST28147_CNT => None,
            Self::KUZNYECHIK_MGM_L => None,
            Self::KUZNYECHIK_MGM_S => None,
            Self::MAGMA_MGM_L => None,
            Self::MAGMA_MGM_S => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NULL => "NULL",
            Self::RC4_40 => "RC4_40",
            Self::RC4_128 => "RC4_128",
            Self::RC2_CBC_40 => "RC2_CBC_40",
            Self::DES40_CBC => "DES40_CBC",
            Self::DES_CBC => "DES_CBC",
            Self::IDEA_CBC => "IDEA_CBC",
            Self::TRIPLEDES_EDE_CBC => "3DES_EDE_CBC",
            Self::AES_128_CBC => "AES_128_CBC",
            Self::AES_256_CBC => "AES_256_CBC",
            Self::AES_128_GCM => "AES_128_GCM",
            Self::AES_256_GCM => "AES_256_GCM",
            Self::AES_128_CCM => "AES_128_CCM",
            Self::AES_256_CCM => "AES_256_CCM",
            Self::AES_128_CCM_8 => "AES_128_CCM_8",
            Self::AES_256_CCM_8 => "AES_256_CCM_8",
            Self::CAMELLIA_128_CBC => "CAMELLIA_128_CBC",
            Self::CAMELLIA_256_CBC => "CAMELLIA_256_CBC",
            Self::CAMELLIA_128_GCM => "CAMELLIA_128_GCM",
            Self::CAMELLIA_256_GCM => "CAMELLIA_256_GCM",
            Self::ARIA_128_CBC => "ARIA_128_CBC",
            Self::ARIA_256_CBC => "ARIA_256_CBC",
            Self::ARIA_128_GCM => "ARIA_128_GCM",
            Self::ARIA_256_GCM => "ARIA_256_GCM",
            Self::SEED_CBC => "SEED_CBC",
            Self::CHACHA20_POLY1305 => "CHACHA20_POLY1305",
            Self::SM4_GCM => "SM4_GCM",
            Self::SM4_CCM => "SM4_CCM",
            Self::AEGIS_128L => "AEGIS_128L",
            Self::AEGIS_256 => "AEGIS_256",
            Self::ASCONAEAD128 => "ASCONAEAD128",
            Self::KUZNYECHIK_CTR_ACPKM => "KUZNYECHIK_CTR",
            Self::MAGMA_CTR_ACPKM => "MAGMA_CTR",
            Self::GOST28147_CNT => "28147_CNT",
            Self::KUZNYECHIK_MGM_L => "KUZNYECHIK_MGM_L",
            Self::KUZNYECHIK_MGM_S => "KUZNYECHIK_MGM_S",
            Self::MAGMA_MGM_L => "MAGMA_MGM_L",
            Self::MAGMA_MGM_S => "MAGMA_MGM_S",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|value| value.as_str() == name)
    }
}

impl fmt::Display for TLSEncryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSMAC {
    HMAC_MD5,
    HMAC_SHA1,
    HMAC_SHA256,
    HMAC_SHA384,
    OMAC_KUZNYECHIK,
    OMAC_MAGMA,
    IMIT_GOST28147,
}

impl TLSMAC {
    pub const ALL: [Self; 7] = [Self::HMAC_MD5, Self::HMAC_SHA1, Self::HMAC_SHA256, Self::HMAC_SHA384, Self::OMAC_KUZNYECHIK, Self::OMAC_MAGMA, Self::IMIT_GOST28147];

    pub fn size(&self) -> usize {
        match self {
            Self::HMAC_MD5 => 16,
            Self::HMAC_SHA1 => 20,
            Self::HMAC_SHA256 => 32,
            Self::HMAC_SHA384 => 48,
            Self::OMAC_KUZNYECHIK => 16,
            Self::OMAC_MAGMA => 8,
            Self::IMIT_GOST28147 => 4,
        }
    }

    pub fn key_size(&self) -> usize {
        match self {
            Self::HMAC_MD5 => 16,
            Self::HMAC_SHA1 => 20,
            Self::HMAC_SHA256 => 32,
            Self::HMAC_SHA384 => 48,
            Self::OMAC_KUZNYECHIK => 32,
            Self::OMAC_MAGMA => 32,
            Self::IMIT_GOST28147 => 32,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HMAC_MD5 => "HMAC_MD5",
            Self::HMAC_SHA1 => "HMAC_SHA1",
            Self::HMAC_SHA256 => "HMAC_SHA256",
            Self::HMAC_SHA384 => "HMAC_SHA384",
            Self::OMAC_KUZNYECHIK => "OMAC_KUZNYECHIK",
            Self::OMAC_MAGMA => "OMAC_MAGMA",
            Self::IMIT_GOST28147 => "IMIT_GOST28147",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|value| value.as_str() == name)
    }
}

impl fmt::Display for TLSMAC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSHash {
    MD5_SHA1,
    SHA256,
    SHA384,
    SHA512,
    SM3,
    STREEBOG256,
    ASCONHASH256,
}

impl TLSHash {
    pub const ALL: [Self; 7] = [Self::MD5_SHA1, Self::SHA256, Self::SHA384, Self::SHA512, Self::SM3, Self::STREEBOG256, Self::ASCONHASH256];

    pub fn digest_size(&self) -> usize {
        match self {
            Self::MD5_SHA1 => 36,
            Self::SHA256 => 32,
            Self::SHA384 => 48,
            Self::SHA512 => 64,
            Self::SM3 => 32,
            Self::STREEBOG256 => 32,
            Self::ASCONHASH256 => 32,
        }
    }

    pub fn hmac(&self) -> Option<HMACHash> {
        match self {
            Self::MD5_SHA1 => None,
            Self::SHA256 => Some(HMACHash::SHA2_256),
            Self::SHA384 => Some(HMACHash::SHA2_384),
            Self::SHA512 => Some(HMACHash::SHA2_512),
            Self::SM3 => Some(HMACHash::SM3),
            Self::STREEBOG256 => Some(HMACHash::Streebog256),
            Self::ASCONHASH256 => Some(HMACHash::AsconHash256),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MD5_SHA1 => "MD5_SHA1",
            Self::SHA256 => "SHA256",
            Self::SHA384 => "SHA384",
            Self::SHA512 => "SHA512",
            Self::SM3 => "SM3",
            Self::STREEBOG256 => "STREEBOG256",
            Self::ASCONHASH256 => "ASCONHASH256",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|value| value.as_str() == name)
    }
}

impl fmt::Display for TLSHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TLSCipherSpecification {
    pub number: u16,
    pub name: &'static str,
    pub key_exchange: Option<TLSKeyExchange>,
    pub encryption: TLSEncryption,
    pub mac: Option<TLSMAC>,
    pub hash: Option<TLSHash>,
    pub versions: &'static [TLSVersion],
    pub export: bool,
    pub signaling: bool,
    pub datagram: bool,
    pub recommendation: TLSRecommendation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSCipher {
    TLS_NULL_WITH_NULL_NULL,
    TLS_RSA_WITH_NULL_MD5,
    TLS_RSA_WITH_NULL_SHA,
    TLS_RSA_EXPORT_WITH_RC4_40_MD5,
    TLS_RSA_WITH_RC4_128_MD5,
    TLS_RSA_WITH_RC4_128_SHA,
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
    TLS_RSA_WITH_IDEA_CBC_SHA,
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
    TLS_RSA_WITH_DES_CBC_SHA,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DH_DSS_WITH_DES_CBC_SHA,
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DH_RSA_WITH_DES_CBC_SHA,
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DHE_DSS_WITH_DES_CBC_SHA,
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DHE_RSA_WITH_DES_CBC_SHA,
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
    TLS_DH_anon_WITH_RC4_128_MD5,
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
    TLS_DH_anon_WITH_DES_CBC_SHA,
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
    TLS_KRB5_WITH_DES_CBC_SHA,
    TLS_KRB5_WITH_3DES_EDE_CBC_SHA,
    TLS_KRB5_WITH_RC4_128_SHA,
    TLS_KRB5_WITH_IDEA_CBC_SHA,
    TLS_KRB5_WITH_DES_CBC_MD5,
    TLS_KRB5_WITH_3DES_EDE_CBC_MD5,
    TLS_KRB5_WITH_RC4_128_MD5,
    TLS_KRB5_WITH_IDEA_CBC_MD5,
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA,
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA,
    TLS_KRB5_EXPORT_WITH_RC4_40_SHA,
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5,
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5,
    TLS_KRB5_EXPORT_WITH_RC4_40_MD5,
    TLS_PSK_WITH_NULL_SHA,
    TLS_DHE_PSK_WITH_NULL_SHA,
    TLS_RSA_PSK_WITH_NULL_SHA,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_DH_DSS_WITH_AES_128_CBC_SHA,
    TLS_DH_RSA_WITH_AES_128_CBC_SHA,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_DH_anon_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_DH_DSS_WITH_AES_256_CBC_SHA,
    TLS_DH_RSA_WITH_AES_256_CBC_SHA,
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_DH_anon_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_NULL_SHA256,
    TLS_RSA_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_AES_256_CBC_SHA256,
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
    TLS_DH_anon_WITH_AES_128_CBC_SHA256,
    TLS_DH_anon_WITH_AES_256_CBC_SHA256,
    TLS_ASCONAEAD128_ASCONHASH256,
    TLS_ASCONAEAD128_SHA256,
    TLS_AES_128_GCM_ASCONHASH256,
    TLS_AES_128_CCM_ASCONHASH256,
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA,
    TLS_PSK_WITH_RC4_128_SHA,
    TLS_PSK_WITH_3DES_EDE_CBC_SHA,
    TLS_PSK_WITH_AES_128_CBC_SHA,
    TLS_PSK_WITH_AES_256_CBC_SHA,
    TLS_DHE_PSK_WITH_RC4_128_SHA,
    TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
    TLS_RSA_PSK_WITH_RC4_128_SHA,
    TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_SEED_CBC_SHA,
    TLS_DH_DSS_WITH_SEED_CBC_SHA,
    TLS_DH_RSA_WITH_SEED_CBC_SHA,
    TLS_DHE_DSS_WITH_SEED_CBC_SHA,
    TLS_DHE_RSA_WITH_SEED_CBC_SHA,
    TLS_DH_anon_WITH_SEED_CBC_SHA,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
    TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
    TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
    TLS_DH_anon_WITH_AES_128_GCM_SHA256,
    TLS_DH_anon_WITH_AES_256_GCM_SHA384,
    TLS_PSK_WITH_AES_128_GCM_SHA256,
    TLS_PSK_WITH_AES_256_GCM_SHA384,
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
    TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
    TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
    TLS_PSK_WITH_AES_128_CBC_SHA256,
    TLS_PSK_WITH_AES_256_CBC_SHA384,
    TLS_PSK_WITH_NULL_SHA256,
    TLS_PSK_WITH_NULL_SHA384,
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
    TLS_DHE_PSK_WITH_NULL_SHA256,
    TLS_DHE_PSK_WITH_NULL_SHA384,
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
    TLS_RSA_PSK_WITH_NULL_SHA256,
    TLS_RSA_PSK_WITH_NULL_SHA384,
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256,
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256,
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256,
    TLS_SM4_GCM_SM3,
    TLS_SM4_CCM_SM3,
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_AES_128_CCM_SHA256,
    TLS_AES_128_CCM_8_SHA256,
    TLS_AEGIS_256_SHA512,
    TLS_AEGIS_128L_SHA256,
    TLS_FALLBACK_SCSV,
    TLS_ECDH_ECDSA_WITH_NULL_SHA,
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_NULL_SHA,
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDH_RSA_WITH_NULL_SHA,
    TLS_ECDH_RSA_WITH_RC4_128_SHA,
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_NULL_SHA,
    TLS_ECDHE_RSA_WITH_RC4_128_SHA,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDH_anon_WITH_NULL_SHA,
    TLS_ECDH_anon_WITH_RC4_128_SHA,
    TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA,
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
    TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
    TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
    TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
    TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
    TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
    TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
    TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
    TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_PSK_WITH_RC4_128_SHA,
    TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_PSK_WITH_NULL_SHA,
    TLS_ECDHE_PSK_WITH_NULL_SHA256,
    TLS_ECDHE_PSK_WITH_NULL_SHA384,
    TLS_RSA_WITH_ARIA_128_CBC_SHA256,
    TLS_RSA_WITH_ARIA_256_CBC_SHA384,
    TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256,
    TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384,
    TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256,
    TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384,
    TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256,
    TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384,
    TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256,
    TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384,
    TLS_DH_anon_WITH_ARIA_128_CBC_SHA256,
    TLS_DH_anon_WITH_ARIA_256_CBC_SHA384,
    TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384,
    TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256,
    TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384,
    TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384,
    TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256,
    TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384,
    TLS_RSA_WITH_ARIA_128_GCM_SHA256,
    TLS_RSA_WITH_ARIA_256_GCM_SHA384,
    TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
    TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
    TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256,
    TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384,
    TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256,
    TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384,
    TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256,
    TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384,
    TLS_DH_anon_WITH_ARIA_128_GCM_SHA256,
    TLS_DH_anon_WITH_ARIA_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
    TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256,
    TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
    TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256,
    TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384,
    TLS_PSK_WITH_ARIA_128_CBC_SHA256,
    TLS_PSK_WITH_ARIA_256_CBC_SHA384,
    TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256,
    TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384,
    TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256,
    TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384,
    TLS_PSK_WITH_ARIA_128_GCM_SHA256,
    TLS_PSK_WITH_ARIA_256_GCM_SHA384,
    TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
    TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
    TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
    TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
    TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256,
    TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384,
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
    TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384,
    TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,
    TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384,
    TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
    TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
    TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
    TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
    TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256,
    TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384,
    TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256,
    TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384,
    TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256,
    TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
    TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
    TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
    TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256,
    TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384,
    TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256,
    TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384,
    TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256,
    TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384,
    TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384,
    TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
    TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
    TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
    TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
    TLS_RSA_WITH_AES_128_CCM,
    TLS_RSA_WITH_AES_256_CCM,
    TLS_DHE_RSA_WITH_AES_128_CCM,
    TLS_DHE_RSA_WITH_AES_256_CCM,
    TLS_RSA_WITH_AES_128_CCM_8,
    TLS_RSA_WITH_AES_256_CCM_8,
    TLS_DHE_RSA_WITH_AES_128_CCM_8,
    TLS_DHE_RSA_WITH_AES_256_CCM_8,
    TLS_PSK_WITH_AES_128_CCM,
    TLS_PSK_WITH_AES_256_CCM,
    TLS_DHE_PSK_WITH_AES_128_CCM,
    TLS_DHE_PSK_WITH_AES_256_CCM,
    TLS_PSK_WITH_AES_128_CCM_8,
    TLS_PSK_WITH_AES_256_CCM_8,
    TLS_PSK_DHE_WITH_AES_128_CCM_8,
    TLS_PSK_DHE_WITH_AES_256_CCM_8,
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
    TLS_ECCPWD_WITH_AES_128_GCM_SHA256,
    TLS_ECCPWD_WITH_AES_256_GCM_SHA384,
    TLS_ECCPWD_WITH_AES_128_CCM_SHA256,
    TLS_ECCPWD_WITH_AES_256_CCM_SHA384,
    TLS_SHA256_SHA256,
    TLS_SHA384_SHA384,
    TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC,
    TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC,
    TLS_GOSTR341112_256_WITH_28147_CNT_IMIT,
    TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L,
    TLS_GOSTR341112_256_WITH_MAGMA_MGM_L,
    TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S,
    TLS_GOSTR341112_256_WITH_MAGMA_MGM_S,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
    TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
    TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256,
    TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256,
}

impl TLSCipher {
    pub const ALL: [Self; 356] = [
        Self::TLS_NULL_WITH_NULL_NULL,
        Self::TLS_RSA_WITH_NULL_MD5,
        Self::TLS_RSA_WITH_NULL_SHA,
        Self::TLS_RSA_EXPORT_WITH_RC4_40_MD5,
        Self::TLS_RSA_WITH_RC4_128_MD5,
        Self::TLS_RSA_WITH_RC4_128_SHA,
        Self::TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
        Self::TLS_RSA_WITH_IDEA_CBC_SHA,
        Self::TLS_RSA_EXPORT_WITH_DES40_CBC_SHA,
        Self::TLS_RSA_WITH_DES_CBC_SHA,
        Self::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        Self::TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA,
        Self::TLS_DH_DSS_WITH_DES_CBC_SHA,
        Self::TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA,
        Self::TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA,
        Self::TLS_DH_RSA_WITH_DES_CBC_SHA,
        Self::TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA,
        Self::TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA,
        Self::TLS_DHE_DSS_WITH_DES_CBC_SHA,
        Self::TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
        Self::TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA,
        Self::TLS_DHE_RSA_WITH_DES_CBC_SHA,
        Self::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
        Self::TLS_DH_anon_EXPORT_WITH_RC4_40_MD5,
        Self::TLS_DH_anon_WITH_RC4_128_MD5,
        Self::TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA,
        Self::TLS_DH_anon_WITH_DES_CBC_SHA,
        Self::TLS_DH_anon_WITH_3DES_EDE_CBC_SHA,
        Self::TLS_KRB5_WITH_DES_CBC_SHA,
        Self::TLS_KRB5_WITH_3DES_EDE_CBC_SHA,
        Self::TLS_KRB5_WITH_RC4_128_SHA,
        Self::TLS_KRB5_WITH_IDEA_CBC_SHA,
        Self::TLS_KRB5_WITH_DES_CBC_MD5,
        Self::TLS_KRB5_WITH_3DES_EDE_CBC_MD5,
        Self::TLS_KRB5_WITH_RC4_128_MD5,
        Self::TLS_KRB5_WITH_IDEA_CBC_MD5,
        Self::TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA,
        Self::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA,
        Self::TLS_KRB5_EXPORT_WITH_RC4_40_SHA,
        Self::TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5,
        Self::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5,
        Self::TLS_KRB5_EXPORT_WITH_RC4_40_MD5,
        Self::TLS_PSK_WITH_NULL_SHA,
        Self::TLS_DHE_PSK_WITH_NULL_SHA,
        Self::TLS_RSA_PSK_WITH_NULL_SHA,
        Self::TLS_RSA_WITH_AES_128_CBC_SHA,
        Self::TLS_DH_DSS_WITH_AES_128_CBC_SHA,
        Self::TLS_DH_RSA_WITH_AES_128_CBC_SHA,
        Self::TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
        Self::TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
        Self::TLS_DH_anon_WITH_AES_128_CBC_SHA,
        Self::TLS_RSA_WITH_AES_256_CBC_SHA,
        Self::TLS_DH_DSS_WITH_AES_256_CBC_SHA,
        Self::TLS_DH_RSA_WITH_AES_256_CBC_SHA,
        Self::TLS_DHE_DSS_WITH_AES_256_CBC_SHA,
        Self::TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
        Self::TLS_DH_anon_WITH_AES_256_CBC_SHA,
        Self::TLS_RSA_WITH_NULL_SHA256,
        Self::TLS_RSA_WITH_AES_128_CBC_SHA256,
        Self::TLS_RSA_WITH_AES_256_CBC_SHA256,
        Self::TLS_DH_DSS_WITH_AES_128_CBC_SHA256,
        Self::TLS_DH_RSA_WITH_AES_128_CBC_SHA256,
        Self::TLS_DHE_DSS_WITH_AES_128_CBC_SHA256,
        Self::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA,
        Self::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA,
        Self::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA,
        Self::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA,
        Self::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA,
        Self::TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA,
        Self::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
        Self::TLS_DH_DSS_WITH_AES_256_CBC_SHA256,
        Self::TLS_DH_RSA_WITH_AES_256_CBC_SHA256,
        Self::TLS_DHE_DSS_WITH_AES_256_CBC_SHA256,
        Self::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
        Self::TLS_DH_anon_WITH_AES_128_CBC_SHA256,
        Self::TLS_DH_anon_WITH_AES_256_CBC_SHA256,
        Self::TLS_ASCONAEAD128_ASCONHASH256,
        Self::TLS_ASCONAEAD128_SHA256,
        Self::TLS_AES_128_GCM_ASCONHASH256,
        Self::TLS_AES_128_CCM_ASCONHASH256,
        Self::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA,
        Self::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA,
        Self::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA,
        Self::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA,
        Self::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA,
        Self::TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA,
        Self::TLS_PSK_WITH_RC4_128_SHA,
        Self::TLS_PSK_WITH_3DES_EDE_CBC_SHA,
        Self::TLS_PSK_WITH_AES_128_CBC_SHA,
        Self::TLS_PSK_WITH_AES_256_CBC_SHA,
        Self::TLS_DHE_PSK_WITH_RC4_128_SHA,
        Self::TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA,
        Self::TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
        Self::TLS_DHE_PSK_WITH_AES_256_CBC_SHA,
        Self::TLS_RSA_PSK_WITH_RC4_128_SHA,
        Self::TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA,
        Self::TLS_RSA_PSK_WITH_AES_128_CBC_SHA,
        Self::TLS_RSA_PSK_WITH_AES_256_CBC_SHA,
        Self::TLS_RSA_WITH_SEED_CBC_SHA,
        Self::TLS_DH_DSS_WITH_SEED_CBC_SHA,
        Self::TLS_DH_RSA_WITH_SEED_CBC_SHA,
        Self::TLS_DHE_DSS_WITH_SEED_CBC_SHA,
        Self::TLS_DHE_RSA_WITH_SEED_CBC_SHA,
        Self::TLS_DH_anon_WITH_SEED_CBC_SHA,
        Self::TLS_RSA_WITH_AES_128_GCM_SHA256,
        Self::TLS_RSA_WITH_AES_256_GCM_SHA384,
        Self::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        Self::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        Self::TLS_DH_RSA_WITH_AES_128_GCM_SHA256,
        Self::TLS_DH_RSA_WITH_AES_256_GCM_SHA384,
        Self::TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
        Self::TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
        Self::TLS_DH_DSS_WITH_AES_128_GCM_SHA256,
        Self::TLS_DH_DSS_WITH_AES_256_GCM_SHA384,
        Self::TLS_DH_anon_WITH_AES_128_GCM_SHA256,
        Self::TLS_DH_anon_WITH_AES_256_GCM_SHA384,
        Self::TLS_PSK_WITH_AES_128_GCM_SHA256,
        Self::TLS_PSK_WITH_AES_256_GCM_SHA384,
        Self::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
        Self::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
        Self::TLS_RSA_PSK_WITH_AES_128_GCM_SHA256,
        Self::TLS_RSA_PSK_WITH_AES_256_GCM_SHA384,
        Self::TLS_PSK_WITH_AES_128_CBC_SHA256,
        Self::TLS_PSK_WITH_AES_256_CBC_SHA384,
        Self::TLS_PSK_WITH_NULL_SHA256,
        Self::TLS_PSK_WITH_NULL_SHA384,
        Self::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256,
        Self::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384,
        Self::TLS_DHE_PSK_WITH_NULL_SHA256,
        Self::TLS_DHE_PSK_WITH_NULL_SHA384,
        Self::TLS_RSA_PSK_WITH_AES_128_CBC_SHA256,
        Self::TLS_RSA_PSK_WITH_AES_256_CBC_SHA384,
        Self::TLS_RSA_PSK_WITH_NULL_SHA256,
        Self::TLS_RSA_PSK_WITH_NULL_SHA384,
        Self::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256,
        Self::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256,
        Self::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
        Self::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256,
        Self::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
        Self::TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256,
        Self::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256,
        Self::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256,
        Self::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256,
        Self::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256,
        Self::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256,
        Self::TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256,
        Self::TLS_SM4_GCM_SM3,
        Self::TLS_SM4_CCM_SM3,
        Self::TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
        Self::TLS_AES_128_GCM_SHA256,
        Self::TLS_AES_256_GCM_SHA384,
        Self::TLS_CHACHA20_POLY1305_SHA256,
        Self::TLS_AES_128_CCM_SHA256,
        Self::TLS_AES_128_CCM_8_SHA256,
        Self::TLS_AEGIS_256_SHA512,
        Self::TLS_AEGIS_128L_SHA256,
        Self::TLS_FALLBACK_SCSV,
        Self::TLS_ECDH_ECDSA_WITH_NULL_SHA,
        Self::TLS_ECDH_ECDSA_WITH_RC4_128_SHA,
        Self::TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA,
        Self::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA,
        Self::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,
        Self::TLS_ECDHE_ECDSA_WITH_NULL_SHA,
        Self::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
        Self::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
        Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
        Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
        Self::TLS_ECDH_RSA_WITH_NULL_SHA,
        Self::TLS_ECDH_RSA_WITH_RC4_128_SHA,
        Self::TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA,
        Self::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,
        Self::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,
        Self::TLS_ECDHE_RSA_WITH_NULL_SHA,
        Self::TLS_ECDHE_RSA_WITH_RC4_128_SHA,
        Self::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
        Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        Self::TLS_ECDH_anon_WITH_NULL_SHA,
        Self::TLS_ECDH_anon_WITH_RC4_128_SHA,
        Self::TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA,
        Self::TLS_ECDH_anon_WITH_AES_128_CBC_SHA,
        Self::TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
        Self::TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA,
        Self::TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA,
        Self::TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA,
        Self::TLS_SRP_SHA_WITH_AES_128_CBC_SHA,
        Self::TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA,
        Self::TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA,
        Self::TLS_SRP_SHA_WITH_AES_256_CBC_SHA,
        Self::TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA,
        Self::TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA,
        Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
        Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
        Self::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,
        Self::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,
        Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
        Self::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,
        Self::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,
        Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        Self::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256,
        Self::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,
        Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        Self::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,
        Self::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,
        Self::TLS_ECDHE_PSK_WITH_RC4_128_SHA,
        Self::TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA,
        Self::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA,
        Self::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA,
        Self::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
        Self::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384,
        Self::TLS_ECDHE_PSK_WITH_NULL_SHA,
        Self::TLS_ECDHE_PSK_WITH_NULL_SHA256,
        Self::TLS_ECDHE_PSK_WITH_NULL_SHA384,
        Self::TLS_RSA_WITH_ARIA_128_CBC_SHA256,
        Self::TLS_RSA_WITH_ARIA_256_CBC_SHA384,
        Self::TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256,
        Self::TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384,
        Self::TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256,
        Self::TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384,
        Self::TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256,
        Self::TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384,
        Self::TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256,
        Self::TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384,
        Self::TLS_DH_anon_WITH_ARIA_128_CBC_SHA256,
        Self::TLS_DH_anon_WITH_ARIA_256_CBC_SHA384,
        Self::TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256,
        Self::TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384,
        Self::TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256,
        Self::TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384,
        Self::TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256,
        Self::TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384,
        Self::TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256,
        Self::TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384,
        Self::TLS_RSA_WITH_ARIA_128_GCM_SHA256,
        Self::TLS_RSA_WITH_ARIA_256_GCM_SHA384,
        Self::TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256,
        Self::TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384,
        Self::TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256,
        Self::TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384,
        Self::TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256,
        Self::TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384,
        Self::TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256,
        Self::TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384,
        Self::TLS_DH_anon_WITH_ARIA_128_GCM_SHA256,
        Self::TLS_DH_anon_WITH_ARIA_256_GCM_SHA384,
        Self::TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256,
        Self::TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384,
        Self::TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256,
        Self::TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384,
        Self::TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256,
        Self::TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384,
        Self::TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256,
        Self::TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384,
        Self::TLS_PSK_WITH_ARIA_128_CBC_SHA256,
        Self::TLS_PSK_WITH_ARIA_256_CBC_SHA384,
        Self::TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256,
        Self::TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384,
        Self::TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256,
        Self::TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384,
        Self::TLS_PSK_WITH_ARIA_128_GCM_SHA256,
        Self::TLS_PSK_WITH_ARIA_256_GCM_SHA384,
        Self::TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256,
        Self::TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384,
        Self::TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256,
        Self::TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384,
        Self::TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256,
        Self::TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384,
        Self::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
        Self::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
        Self::TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256,
        Self::TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384,
        Self::TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256,
        Self::TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384,
        Self::TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256,
        Self::TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384,
        Self::TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256,
        Self::TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384,
        Self::TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
        Self::TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
        Self::TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
        Self::TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
        Self::TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256,
        Self::TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384,
        Self::TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256,
        Self::TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384,
        Self::TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256,
        Self::TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384,
        Self::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
        Self::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
        Self::TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256,
        Self::TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384,
        Self::TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256,
        Self::TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384,
        Self::TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256,
        Self::TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384,
        Self::TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256,
        Self::TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384,
        Self::TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256,
        Self::TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384,
        Self::TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256,
        Self::TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384,
        Self::TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256,
        Self::TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384,
        Self::TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
        Self::TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
        Self::TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256,
        Self::TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384,
        Self::TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256,
        Self::TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384,
        Self::TLS_RSA_WITH_AES_128_CCM,
        Self::TLS_RSA_WITH_AES_256_CCM,
        Self::TLS_DHE_RSA_WITH_AES_128_CCM,
        Self::TLS_DHE_RSA_WITH_AES_256_CCM,
        Self::TLS_RSA_WITH_AES_128_CCM_8,
        Self::TLS_RSA_WITH_AES_256_CCM_8,
        Self::TLS_DHE_RSA_WITH_AES_128_CCM_8,
        Self::TLS_DHE_RSA_WITH_AES_256_CCM_8,
        Self::TLS_PSK_WITH_AES_128_CCM,
        Self::TLS_PSK_WITH_AES_256_CCM,
        Self::TLS_DHE_PSK_WITH_AES_128_CCM,
        Self::TLS_DHE_PSK_WITH_AES_256_CCM,
        Self::TLS_PSK_WITH_AES_128_CCM_8,
        Self::TLS_PSK_WITH_AES_256_CCM_8,
        Self::TLS_PSK_DHE_WITH_AES_128_CCM_8,
        Self::TLS_PSK_DHE_WITH_AES_256_CCM_8,
        Self::TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
        Self::TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
        Self::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
        Self::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
        Self::TLS_ECCPWD_WITH_AES_128_GCM_SHA256,
        Self::TLS_ECCPWD_WITH_AES_256_GCM_SHA384,
        Self::TLS_ECCPWD_WITH_AES_128_CCM_SHA256,
        Self::TLS_ECCPWD_WITH_AES_256_CCM_SHA384,
        Self::TLS_SHA256_SHA256,
        Self::TLS_SHA384_SHA384,
        Self::TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC,
        Self::TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC,
        Self::TLS_GOSTR341112_256_WITH_28147_CNT_IMIT,
        Self::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L,
        Self::TLS_GOSTR341112_256_WITH_MAGMA_MGM_L,
        Self::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S,
        Self::TLS_GOSTR341112_256_WITH_MAGMA_MGM_S,
        Self::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        Self::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        Self::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        Self::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
        Self::TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
        Self::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
        Self::TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256,
        Self::TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
        Self::TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
        Self::TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256,
        Self::TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256,
    ];

    pub fn specification(&self) -> TLSCipherSpecification {
        match self {
            Self::TLS_NULL_WITH_NULL_NULL => TLSCipherSpecification { number: 0x0000, name: "TLS_NULL_WITH_NULL_NULL", key_exchange: None, encryption: TLSEncryption::NULL, mac: None, hash: None, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_RSA_WITH_NULL_MD5 => TLSCipherSpecification { number: 0x0001, name: "TLS_RSA_WITH_NULL_MD5", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_MD5), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_NULL_SHA => TLSCipherSpecification { number: 0x0002, name: "TLS_RSA_WITH_NULL_SHA", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_EXPORT_WITH_RC4_40_MD5 => TLSCipherSpecification { number: 0x0003, name: "TLS_RSA_EXPORT_WITH_RC4_40_MD5", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::RC4_40, mac: Some(TLSMAC::HMAC_MD5), hash: None, versions: &[TLSVersion::V1_0], export: true, signaling: false, datagram: false, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_RC4_128_MD5 => TLSCipherSpecification { number: 0x0004, name: "TLS_RSA_WITH_RC4_128_MD5", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::RC4_128, mac: Some(TLSMAC::HMAC_MD5), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_RC4_128_SHA => TLSCipherSpecification { number: 0x0005, name: "TLS_RSA_WITH_RC4_128_SHA", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::RC4_128, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 => TLSCipherSpecification { number: 0x0006, name: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::RC2_CBC_40, mac: Some(TLSMAC::HMAC_MD5), hash: None, versions: &[TLSVersion::V1_0], export: true, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_IDEA_CBC_SHA => TLSCipherSpecification { number: 0x0007, name: "TLS_RSA_WITH_IDEA_CBC_SHA", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::IDEA_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: None, versions: &[TLSVersion::V1_0, TLSVersion::V1_1], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_EXPORT_WITH_DES40_CBC_SHA => TLSCipherSpecification { number: 0x0008, name: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::DES40_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: None, versions: &[TLSVersion::V1_0], export: true, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_DES_CBC_SHA => TLSCipherSpecification { number: 0x0009, name: "TLS_RSA_WITH_DES_CBC_SHA", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::DES_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: None, versions: &[TLSVersion::V1_0, TLSVersion::V1_1], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_3DES_EDE_CBC_SHA => TLSCipherSpecification { number: 0x000A, name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA => TLSCipherSpecification { number: 0x000B, name: "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::DES40_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: None, versions: &[TLSVersion::V1_0], export: true, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_WITH_DES_CBC_SHA => TLSCipherSpecification { number: 0x000C, name: "TLS_DH_DSS_WITH_DES_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::DES_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: None, versions: &[TLSVersion::V1_0, TLSVersion::V1_1], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA => TLSCipherSpecification { number: 0x000D, name: "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA => TLSCipherSpecification { number: 0x000E, name: "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::DES40_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: None, versions: &[TLSVersion::V1_0], export: true, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_WITH_DES_CBC_SHA => TLSCipherSpecification { number: 0x000F, name: "TLS_DH_RSA_WITH_DES_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::DES_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: None, versions: &[TLSVersion::V1_0, TLSVersion::V1_1], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA => TLSCipherSpecification { number: 0x0010, name: "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA => TLSCipherSpecification { number: 0x0011, name: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::DES40_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: None, versions: &[TLSVersion::V1_0], export: true, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_WITH_DES_CBC_SHA => TLSCipherSpecification { number: 0x0012, name: "TLS_DHE_DSS_WITH_DES_CBC_SHA", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::DES_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: None, versions: &[TLSVersion::V1_0, TLSVersion::V1_1], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA => TLSCipherSpecification { number: 0x0013, name: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA => TLSCipherSpecification { number: 0x0014, name: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::DES40_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: None, versions: &[TLSVersion::V1_0], export: true, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_DES_CBC_SHA => TLSCipherSpecification { number: 0x0015, name: "TLS_DHE_RSA_WITH_DES_CBC_SHA", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::DES_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: None, versions: &[TLSVersion::V1_0, TLSVersion::V1_1], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA => TLSCipherSpecification { number: 0x0016, name: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_EXPORT_WITH_RC4_40_MD5 => TLSCipherSpecification { number: 0x0017, name: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::RC4_40, mac: Some(TLSMAC::HMAC_MD5), hash: None, versions: &[TLSVersion::V1_0], export: true, signaling: false, datagram: false, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_RC4_128_MD5 => TLSCipherSpecification { number: 0x0018, name: "TLS_DH_anon_WITH_RC4_128_MD5", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::RC4_128, mac: Some(TLSMAC::HMAC_MD5), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA => TLSCipherSpecification { number: 0x0019, name: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::DES40_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: None, versions: &[TLSVersion::V1_0], export: true, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_DES_CBC_SHA => TLSCipherSpecification { number: 0x001A, name: "TLS_DH_anon_WITH_DES_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::DES_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: None, versions: &[TLSVersion::V1_0, TLSVersion::V1_1], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_3DES_EDE_CBC_SHA => TLSCipherSpecification { number: 0x001B, name: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_KRB5_WITH_DES_CBC_SHA => TLSCipherSpecification { number: 0x001E, name: "TLS_KRB5_WITH_DES_CBC_SHA", key_exchange: Some(TLSKeyExchange::KRB5), encryption: TLSEncryption::DES_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: None, versions: &[TLSVersion::V1_0, TLSVersion::V1_1], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_KRB5_WITH_3DES_EDE_CBC_SHA => TLSCipherSpecification { number: 0x001F, name: "TLS_KRB5_WITH_3DES_EDE_CBC_SHA", key_exchange: Some(TLSKeyExchange::KRB5), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_KRB5_WITH_RC4_128_SHA => TLSCipherSpecification { number: 0x0020, name: "TLS_KRB5_WITH_RC4_128_SHA", key_exchange: Some(TLSKeyExchange::KRB5), encryption: TLSEncryption::RC4_128, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_KRB5_WITH_IDEA_CBC_SHA => TLSCipherSpecification { number: 0x0021, name: "TLS_KRB5_WITH_IDEA_CBC_SHA", key_exchange: Some(TLSKeyExchange::KRB5), encryption: TLSEncryption::IDEA_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: None, versions: &[TLSVersion::V1_0, TLSVersion::V1_1], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_KRB5_WITH_DES_CBC_MD5 => TLSCipherSpecification { number: 0x0022, name: "TLS_KRB5_WITH_DES_CBC_MD5", key_exchange: Some(TLSKeyExchange::KRB5), encryption: TLSEncryption::DES_CBC, mac: Some(TLSMAC::HMAC_MD5), hash: None, versions: &[TLSVersion::V1_0, TLSVersion::V1_1], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_KRB5_WITH_3DES_EDE_CBC_MD5 => TLSCipherSpecification { number: 0x0023, name: "TLS_KRB5_WITH_3DES_EDE_CBC_MD5", key_exchange: Some(TLSKeyExchange::KRB5), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_MD5), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_KRB5_WITH_RC4_128_MD5 => TLSCipherSpecification { number: 0x0024, name: "TLS_KRB5_WITH_RC4_128_MD5", key_exchange: Some(TLSKeyExchange::KRB5), encryption: TLSEncryption::RC4_128, mac: Some(TLSMAC::HMAC_MD5), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_KRB5_WITH_IDEA_CBC_MD5 => TLSCipherSpecification { number: 0x0025, name: "TLS_KRB5_WITH_IDEA_CBC_MD5", key_exchange: Some(TLSKeyExchange::KRB5), encryption: TLSEncryption::IDEA_CBC, mac: Some(TLSMAC::HMAC_MD5), hash: None, versions: &[TLSVersion::V1_0, TLSVersion::V1_1], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA => TLSCipherSpecification { number: 0x0026, name: "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA", key_exchange: Some(TLSKeyExchange::KRB5), encryption: TLSEncryption::DES40_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: None, versions: &[TLSVersion::V1_0], export: true, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA => TLSCipherSpecification { number: 0x0027, name: "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA", key_exchange: Some(TLSKeyExchange::KRB5), encryption: TLSEncryption::RC2_CBC_40, mac: Some(TLSMAC::HMAC_SHA1), hash: None, versions: &[TLSVersion::V1_0], export: true, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_KRB5_EXPORT_WITH_RC4_40_SHA => TLSCipherSpecification { number: 0x0028, name: "TLS_KRB5_EXPORT_WITH_RC4_40_SHA", key_exchange: Some(TLSKeyExchange::KRB5), encryption: TLSEncryption::RC4_40, mac: Some(TLSMAC::HMAC_SHA1), hash: None, versions: &[TLSVersion::V1_0], export: true, signaling: false, datagram: false, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5 => TLSCipherSpecification { number: 0x0029, name: "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5", key_exchange: Some(TLSKeyExchange::KRB5), encryption: TLSEncryption::DES40_CBC, mac: Some(TLSMAC::HMAC_MD5), hash: None, versions: &[TLSVersion::V1_0], export: true, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5 => TLSCipherSpecification { number: 0x002A, name: "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5", key_exchange: Some(TLSKeyExchange::KRB5), encryption: TLSEncryption::RC2_CBC_40, mac: Some(TLSMAC::HMAC_MD5), hash: None, versions: &[TLSVersion::V1_0], export: true, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_KRB5_EXPORT_WITH_RC4_40_MD5 => TLSCipherSpecification { number: 0x002B, name: "TLS_KRB5_EXPORT_WITH_RC4_40_MD5", key_exchange: Some(TLSKeyExchange::KRB5), encryption: TLSEncryption::RC4_40, mac: Some(TLSMAC::HMAC_MD5), hash: None, versions: &[TLSVersion::V1_0], export: true, signaling: false, datagram: false, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_PSK_WITH_NULL_SHA => TLSCipherSpecification { number: 0x002C, name: "TLS_PSK_WITH_NULL_SHA", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_PSK_WITH_NULL_SHA => TLSCipherSpecification { number: 0x002D, name: "TLS_DHE_PSK_WITH_NULL_SHA", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_NULL_SHA => TLSCipherSpecification { number: 0x002E, name: "TLS_RSA_PSK_WITH_NULL_SHA", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_AES_128_CBC_SHA => TLSCipherSpecification { number: 0x002F, name: "TLS_RSA_WITH_AES_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_WITH_AES_128_CBC_SHA => TLSCipherSpecification { number: 0x0030, name: "TLS_DH_DSS_WITH_AES_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_WITH_AES_128_CBC_SHA => TLSCipherSpecification { number: 0x0031, name: "TLS_DH_RSA_WITH_AES_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_WITH_AES_128_CBC_SHA => TLSCipherSpecification { number: 0x0032, name: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_AES_128_CBC_SHA => TLSCipherSpecification { number: 0x0033, name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_AES_128_CBC_SHA => TLSCipherSpecification { number: 0x0034, name: "TLS_DH_anon_WITH_AES_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_AES_256_CBC_SHA => TLSCipherSpecification { number: 0x0035, name: "TLS_RSA_WITH_AES_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_WITH_AES_256_CBC_SHA => TLSCipherSpecification { number: 0x0036, name: "TLS_DH_DSS_WITH_AES_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_WITH_AES_256_CBC_SHA => TLSCipherSpecification { number: 0x0037, name: "TLS_DH_RSA_WITH_AES_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_WITH_AES_256_CBC_SHA => TLSCipherSpecification { number: 0x0038, name: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_AES_256_CBC_SHA => TLSCipherSpecification { number: 0x0039, name: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_AES_256_CBC_SHA => TLSCipherSpecification { number: 0x003A, name: "TLS_DH_anon_WITH_AES_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_NULL_SHA256 => TLSCipherSpecification { number: 0x003B, name: "TLS_RSA_WITH_NULL_SHA256", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_AES_128_CBC_SHA256 => TLSCipherSpecification { number: 0x003C, name: "TLS_RSA_WITH_AES_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_AES_256_CBC_SHA256 => TLSCipherSpecification { number: 0x003D, name: "TLS_RSA_WITH_AES_256_CBC_SHA256", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_WITH_AES_128_CBC_SHA256 => TLSCipherSpecification { number: 0x003E, name: "TLS_DH_DSS_WITH_AES_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_WITH_AES_128_CBC_SHA256 => TLSCipherSpecification { number: 0x003F, name: "TLS_DH_RSA_WITH_AES_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 => TLSCipherSpecification { number: 0x0040, name: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA => TLSCipherSpecification { number: 0x0041, name: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA => TLSCipherSpecification { number: 0x0042, name: "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA => TLSCipherSpecification { number: 0x0043, name: "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA => TLSCipherSpecification { number: 0x0044, name: "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA => TLSCipherSpecification { number: 0x0045, name: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA => TLSCipherSpecification { number: 0x0046, name: "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 => TLSCipherSpecification { number: 0x0067, name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_WITH_AES_256_CBC_SHA256 => TLSCipherSpecification { number: 0x0068, name: "TLS_DH_DSS_WITH_AES_256_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_WITH_AES_256_CBC_SHA256 => TLSCipherSpecification { number: 0x0069, name: "TLS_DH_RSA_WITH_AES_256_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 => TLSCipherSpecification { number: 0x006A, name: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 => TLSCipherSpecification { number: 0x006B, name: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_AES_128_CBC_SHA256 => TLSCipherSpecification { number: 0x006C, name: "TLS_DH_anon_WITH_AES_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_AES_256_CBC_SHA256 => TLSCipherSpecification { number: 0x006D, name: "TLS_DH_anon_WITH_AES_256_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ASCONAEAD128_ASCONHASH256 => TLSCipherSpecification { number: 0x006E, name: "TLS_ASCONAEAD128_ASCONHASH256", key_exchange: None, encryption: TLSEncryption::ASCONAEAD128, mac: None, hash: Some(TLSHash::ASCONHASH256), versions: &[TLSVersion::V1_3], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ASCONAEAD128_SHA256 => TLSCipherSpecification { number: 0x006F, name: "TLS_ASCONAEAD128_SHA256", key_exchange: None, encryption: TLSEncryption::ASCONAEAD128, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_3], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_AES_128_GCM_ASCONHASH256 => TLSCipherSpecification { number: 0x0070, name: "TLS_AES_128_GCM_ASCONHASH256", key_exchange: None, encryption: TLSEncryption::AES_128_GCM, mac: None, hash: Some(TLSHash::ASCONHASH256), versions: &[TLSVersion::V1_3], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_AES_128_CCM_ASCONHASH256 => TLSCipherSpecification { number: 0x0071, name: "TLS_AES_128_CCM_ASCONHASH256", key_exchange: None, encryption: TLSEncryption::AES_128_CCM, mac: None, hash: Some(TLSHash::ASCONHASH256), versions: &[TLSVersion::V1_3], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA => TLSCipherSpecification { number: 0x0084, name: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA => TLSCipherSpecification { number: 0x0085, name: "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA => TLSCipherSpecification { number: 0x0086, name: "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA => TLSCipherSpecification { number: 0x0087, name: "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA => TLSCipherSpecification { number: 0x0088, name: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA => TLSCipherSpecification { number: 0x0089, name: "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_PSK_WITH_RC4_128_SHA => TLSCipherSpecification { number: 0x008A, name: "TLS_PSK_WITH_RC4_128_SHA", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::RC4_128, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_PSK_WITH_3DES_EDE_CBC_SHA => TLSCipherSpecification { number: 0x008B, name: "TLS_PSK_WITH_3DES_EDE_CBC_SHA", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_PSK_WITH_AES_128_CBC_SHA => TLSCipherSpecification { number: 0x008C, name: "TLS_PSK_WITH_AES_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_PSK_WITH_AES_256_CBC_SHA => TLSCipherSpecification { number: 0x008D, name: "TLS_PSK_WITH_AES_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_DHE_PSK_WITH_RC4_128_SHA => TLSCipherSpecification { number: 0x008E, name: "TLS_DHE_PSK_WITH_RC4_128_SHA", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::RC4_128, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA => TLSCipherSpecification { number: 0x008F, name: "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_PSK_WITH_AES_128_CBC_SHA => TLSCipherSpecification { number: 0x0090, name: "TLS_DHE_PSK_WITH_AES_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_PSK_WITH_AES_256_CBC_SHA => TLSCipherSpecification { number: 0x0091, name: "TLS_DHE_PSK_WITH_AES_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_RC4_128_SHA => TLSCipherSpecification { number: 0x0092, name: "TLS_RSA_PSK_WITH_RC4_128_SHA", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::RC4_128, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA => TLSCipherSpecification { number: 0x0093, name: "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_AES_128_CBC_SHA => TLSCipherSpecification { number: 0x0094, name: "TLS_RSA_PSK_WITH_AES_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_AES_256_CBC_SHA => TLSCipherSpecification { number: 0x0095, name: "TLS_RSA_PSK_WITH_AES_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_SEED_CBC_SHA => TLSCipherSpecification { number: 0x0096, name: "TLS_RSA_WITH_SEED_CBC_SHA", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::SEED_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_WITH_SEED_CBC_SHA => TLSCipherSpecification { number: 0x0097, name: "TLS_DH_DSS_WITH_SEED_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::SEED_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_WITH_SEED_CBC_SHA => TLSCipherSpecification { number: 0x0098, name: "TLS_DH_RSA_WITH_SEED_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::SEED_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_WITH_SEED_CBC_SHA => TLSCipherSpecification { number: 0x0099, name: "TLS_DHE_DSS_WITH_SEED_CBC_SHA", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::SEED_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_SEED_CBC_SHA => TLSCipherSpecification { number: 0x009A, name: "TLS_DHE_RSA_WITH_SEED_CBC_SHA", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::SEED_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_SEED_CBC_SHA => TLSCipherSpecification { number: 0x009B, name: "TLS_DH_anon_WITH_SEED_CBC_SHA", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::SEED_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_AES_128_GCM_SHA256 => TLSCipherSpecification { number: 0x009C, name: "TLS_RSA_WITH_AES_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::AES_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_AES_256_GCM_SHA384 => TLSCipherSpecification { number: 0x009D, name: "TLS_RSA_WITH_AES_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::AES_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 => TLSCipherSpecification { number: 0x009E, name: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::AES_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 => TLSCipherSpecification { number: 0x009F, name: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::AES_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_WITH_AES_128_GCM_SHA256 => TLSCipherSpecification { number: 0x00A0, name: "TLS_DH_RSA_WITH_AES_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::AES_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_WITH_AES_256_GCM_SHA384 => TLSCipherSpecification { number: 0x00A1, name: "TLS_DH_RSA_WITH_AES_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::AES_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 => TLSCipherSpecification { number: 0x00A2, name: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::AES_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 => TLSCipherSpecification { number: 0x00A3, name: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::AES_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_WITH_AES_128_GCM_SHA256 => TLSCipherSpecification { number: 0x00A4, name: "TLS_DH_DSS_WITH_AES_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::AES_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_WITH_AES_256_GCM_SHA384 => TLSCipherSpecification { number: 0x00A5, name: "TLS_DH_DSS_WITH_AES_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::AES_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_AES_128_GCM_SHA256 => TLSCipherSpecification { number: 0x00A6, name: "TLS_DH_anon_WITH_AES_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::AES_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_AES_256_GCM_SHA384 => TLSCipherSpecification { number: 0x00A7, name: "TLS_DH_anon_WITH_AES_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::AES_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_PSK_WITH_AES_128_GCM_SHA256 => TLSCipherSpecification { number: 0x00A8, name: "TLS_PSK_WITH_AES_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::AES_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_PSK_WITH_AES_256_GCM_SHA384 => TLSCipherSpecification { number: 0x00A9, name: "TLS_PSK_WITH_AES_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::AES_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 => TLSCipherSpecification { number: 0x00AA, name: "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::AES_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 => TLSCipherSpecification { number: 0x00AB, name: "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::AES_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 => TLSCipherSpecification { number: 0x00AC, name: "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::AES_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 => TLSCipherSpecification { number: 0x00AD, name: "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::AES_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_PSK_WITH_AES_128_CBC_SHA256 => TLSCipherSpecification { number: 0x00AE, name: "TLS_PSK_WITH_AES_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_PSK_WITH_AES_256_CBC_SHA384 => TLSCipherSpecification { number: 0x00AF, name: "TLS_PSK_WITH_AES_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_PSK_WITH_NULL_SHA256 => TLSCipherSpecification { number: 0x00B0, name: "TLS_PSK_WITH_NULL_SHA256", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_PSK_WITH_NULL_SHA384 => TLSCipherSpecification { number: 0x00B1, name: "TLS_PSK_WITH_NULL_SHA384", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 => TLSCipherSpecification { number: 0x00B2, name: "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 => TLSCipherSpecification { number: 0x00B3, name: "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_PSK_WITH_NULL_SHA256 => TLSCipherSpecification { number: 0x00B4, name: "TLS_DHE_PSK_WITH_NULL_SHA256", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_PSK_WITH_NULL_SHA384 => TLSCipherSpecification { number: 0x00B5, name: "TLS_DHE_PSK_WITH_NULL_SHA384", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 => TLSCipherSpecification { number: 0x00B6, name: "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 => TLSCipherSpecification { number: 0x00B7, name: "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_NULL_SHA256 => TLSCipherSpecification { number: 0x00B8, name: "TLS_RSA_PSK_WITH_NULL_SHA256", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_NULL_SHA384 => TLSCipherSpecification { number: 0x00B9, name: "TLS_RSA_PSK_WITH_NULL_SHA384", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0x00BA, name: "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0x00BB, name: "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0x00BC, name: "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0x00BD, name: "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0x00BE, name: "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0x00BF, name: "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 => TLSCipherSpecification { number: 0x00C0, name: "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 => TLSCipherSpecification { number: 0x00C1, name: "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256 => TLSCipherSpecification { number: 0x00C2, name: "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256 => TLSCipherSpecification { number: 0x00C3, name: "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 => TLSCipherSpecification { number: 0x00C4, name: "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 => TLSCipherSpecification { number: 0x00C5, name: "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_SM4_GCM_SM3 => TLSCipherSpecification { number: 0x00C6, name: "TLS_SM4_GCM_SM3", key_exchange: None, encryption: TLSEncryption::SM4_GCM, mac: None, hash: Some(TLSHash::SM3), versions: &[TLSVersion::V1_3], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_SM4_CCM_SM3 => TLSCipherSpecification { number: 0x00C7, name: "TLS_SM4_CCM_SM3", key_exchange: None, encryption: TLSEncryption::SM4_CCM, mac: None, hash: Some(TLSHash::SM3), versions: &[TLSVersion::V1_3], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_EMPTY_RENEGOTIATION_INFO_SCSV => TLSCipherSpecification { number: 0x00FF, name: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", key_exchange: None, encryption: TLSEncryption::NULL, mac: None, hash: None, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: true, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_AES_128_GCM_SHA256 => TLSCipherSpecification { number: 0x1301, name: "TLS_AES_128_GCM_SHA256", key_exchange: None, encryption: TLSEncryption::AES_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_3], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Recommended },
            Self::TLS_AES_256_GCM_SHA384 => TLSCipherSpecification { number: 0x1302, name: "TLS_AES_256_GCM_SHA384", key_exchange: None, encryption: TLSEncryption::AES_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_3], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Recommended },
            Self::TLS_CHACHA20_POLY1305_SHA256 => TLSCipherSpecification { number: 0x1303, name: "TLS_CHACHA20_POLY1305_SHA256", key_exchange: None, encryption: TLSEncryption::CHACHA20_POLY1305, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_3], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Recommended },
            Self::TLS_AES_128_CCM_SHA256 => TLSCipherSpecification { number: 0x1304, name: "TLS_AES_128_CCM_SHA256", key_exchange: None, encryption: TLSEncryption::AES_128_CCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_3], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Recommended },
            Self::TLS_AES_128_CCM_8_SHA256 => TLSCipherSpecification { number: 0x1305, name: "TLS_AES_128_CCM_8_SHA256", key_exchange: None, encryption: TLSEncryption::AES_128_CCM_8, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_3], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_AEGIS_256_SHA512 => TLSCipherSpecification { number: 0x1306, name: "TLS_AEGIS_256_SHA512", key_exchange: None, encryption: TLSEncryption::AEGIS_256, mac: None, hash: Some(TLSHash::SHA512), versions: &[TLSVersion::V1_3], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_AEGIS_128L_SHA256 => TLSCipherSpecification { number: 0x1307, name: "TLS_AEGIS_128L_SHA256", key_exchange: None, encryption: TLSEncryption::AEGIS_128L, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_3], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_FALLBACK_SCSV => TLSCipherSpecification { number: 0x5600, name: "TLS_FALLBACK_SCSV", key_exchange: None, encryption: TLSEncryption::NULL, mac: None, hash: None, versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2, TLSVersion::V1_3], export: false, signaling: true, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDH_ECDSA_WITH_NULL_SHA => TLSCipherSpecification { number: 0xC001, name: "TLS_ECDH_ECDSA_WITH_NULL_SHA", key_exchange: Some(TLSKeyExchange::ECDH_ECDSA), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_ECDSA_WITH_RC4_128_SHA => TLSCipherSpecification { number: 0xC002, name: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA", key_exchange: Some(TLSKeyExchange::ECDH_ECDSA), encryption: TLSEncryption::RC4_128, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA => TLSCipherSpecification { number: 0xC003, name: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", key_exchange: Some(TLSKeyExchange::ECDH_ECDSA), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA => TLSCipherSpecification { number: 0xC004, name: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::ECDH_ECDSA), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA => TLSCipherSpecification { number: 0xC005, name: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::ECDH_ECDSA), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_ECDSA_WITH_NULL_SHA => TLSCipherSpecification { number: 0xC006, name: "TLS_ECDHE_ECDSA_WITH_NULL_SHA", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_ECDSA_WITH_RC4_128_SHA => TLSCipherSpecification { number: 0xC007, name: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::RC4_128, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA => TLSCipherSpecification { number: 0xC008, name: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA => TLSCipherSpecification { number: 0xC009, name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA => TLSCipherSpecification { number: 0xC00A, name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDH_RSA_WITH_NULL_SHA => TLSCipherSpecification { number: 0xC00B, name: "TLS_ECDH_RSA_WITH_NULL_SHA", key_exchange: Some(TLSKeyExchange::ECDH_RSA), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_RSA_WITH_RC4_128_SHA => TLSCipherSpecification { number: 0xC00C, name: "TLS_ECDH_RSA_WITH_RC4_128_SHA", key_exchange: Some(TLSKeyExchange::ECDH_RSA), encryption: TLSEncryption::RC4_128, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA => TLSCipherSpecification { number: 0xC00D, name: "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", key_exchange: Some(TLSKeyExchange::ECDH_RSA), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA => TLSCipherSpecification { number: 0xC00E, name: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::ECDH_RSA), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA => TLSCipherSpecification { number: 0xC00F, name: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::ECDH_RSA), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_RSA_WITH_NULL_SHA => TLSCipherSpecification { number: 0xC010, name: "TLS_ECDHE_RSA_WITH_NULL_SHA", key_exchange: Some(TLSKeyExchange::ECDHE_RSA), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_RSA_WITH_RC4_128_SHA => TLSCipherSpecification { number: 0xC011, name: "TLS_ECDHE_RSA_WITH_RC4_128_SHA", key_exchange: Some(TLSKeyExchange::ECDHE_RSA), encryption: TLSEncryption::RC4_128, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA => TLSCipherSpecification { number: 0xC012, name: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", key_exchange: Some(TLSKeyExchange::ECDHE_RSA), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA => TLSCipherSpecification { number: 0xC013, name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::ECDHE_RSA), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA => TLSCipherSpecification { number: 0xC014, name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::ECDHE_RSA), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDH_anon_WITH_NULL_SHA => TLSCipherSpecification { number: 0xC015, name: "TLS_ECDH_anon_WITH_NULL_SHA", key_exchange: Some(TLSKeyExchange::ECDH_anon), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_anon_WITH_RC4_128_SHA => TLSCipherSpecification { number: 0xC016, name: "TLS_ECDH_anon_WITH_RC4_128_SHA", key_exchange: Some(TLSKeyExchange::ECDH_anon), encryption: TLSEncryption::RC4_128, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA => TLSCipherSpecification { number: 0xC017, name: "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", key_exchange: Some(TLSKeyExchange::ECDH_anon), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_anon_WITH_AES_128_CBC_SHA => TLSCipherSpecification { number: 0xC018, name: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::ECDH_anon), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_anon_WITH_AES_256_CBC_SHA => TLSCipherSpecification { number: 0xC019, name: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::ECDH_anon), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA => TLSCipherSpecification { number: 0xC01A, name: "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA", key_exchange: Some(TLSKeyExchange::SRP_SHA), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA => TLSCipherSpecification { number: 0xC01B, name: "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA", key_exchange: Some(TLSKeyExchange::SRP_SHA_RSA), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA => TLSCipherSpecification { number: 0xC01C, name: "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA", key_exchange: Some(TLSKeyExchange::SRP_SHA_DSS), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_SRP_SHA_WITH_AES_128_CBC_SHA => TLSCipherSpecification { number: 0xC01D, name: "TLS_SRP_SHA_WITH_AES_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::SRP_SHA), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA => TLSCipherSpecification { number: 0xC01E, name: "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::SRP_SHA_RSA), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA => TLSCipherSpecification { number: 0xC01F, name: "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::SRP_SHA_DSS), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_SRP_SHA_WITH_AES_256_CBC_SHA => TLSCipherSpecification { number: 0xC020, name: "TLS_SRP_SHA_WITH_AES_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::SRP_SHA), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA => TLSCipherSpecification { number: 0xC021, name: "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::SRP_SHA_RSA), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA => TLSCipherSpecification { number: 0xC022, name: "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::SRP_SHA_DSS), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC023, name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC024, name: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC025, name: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::ECDH_ECDSA), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC026, name: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::ECDH_ECDSA), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC027, name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_RSA), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC028, name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::ECDHE_RSA), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC029, name: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::ECDH_RSA), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC02A, name: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::ECDH_RSA), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC02B, name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::AES_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Recommended },
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC02C, name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::AES_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Recommended },
            Self::TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC02D, name: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::ECDH_ECDSA), encryption: TLSEncryption::AES_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC02E, name: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::ECDH_ECDSA), encryption: TLSEncryption::AES_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC02F, name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_RSA), encryption: TLSEncryption::AES_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Recommended },
            Self::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC030, name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::ECDHE_RSA), encryption: TLSEncryption::AES_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Recommended },
            Self::TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC031, name: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::ECDH_RSA), encryption: TLSEncryption::AES_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC032, name: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::ECDH_RSA), encryption: TLSEncryption::AES_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_PSK_WITH_RC4_128_SHA => TLSCipherSpecification { number: 0xC033, name: "TLS_ECDHE_PSK_WITH_RC4_128_SHA", key_exchange: Some(TLSKeyExchange::ECDHE_PSK), encryption: TLSEncryption::RC4_128, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA => TLSCipherSpecification { number: 0xC034, name: "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA", key_exchange: Some(TLSKeyExchange::ECDHE_PSK), encryption: TLSEncryption::TRIPLEDES_EDE_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA => TLSCipherSpecification { number: 0xC035, name: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", key_exchange: Some(TLSKeyExchange::ECDHE_PSK), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA => TLSCipherSpecification { number: 0xC036, name: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA", key_exchange: Some(TLSKeyExchange::ECDHE_PSK), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC037, name: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_PSK), encryption: TLSEncryption::AES_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC038, name: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::ECDHE_PSK), encryption: TLSEncryption::AES_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_PSK_WITH_NULL_SHA => TLSCipherSpecification { number: 0xC039, name: "TLS_ECDHE_PSK_WITH_NULL_SHA", key_exchange: Some(TLSKeyExchange::ECDHE_PSK), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA1), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_0, TLSVersion::V1_1, TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_PSK_WITH_NULL_SHA256 => TLSCipherSpecification { number: 0xC03A, name: "TLS_ECDHE_PSK_WITH_NULL_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_PSK), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_PSK_WITH_NULL_SHA384 => TLSCipherSpecification { number: 0xC03B, name: "TLS_ECDHE_PSK_WITH_NULL_SHA384", key_exchange: Some(TLSKeyExchange::ECDHE_PSK), encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_ARIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC03C, name: "TLS_RSA_WITH_ARIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::ARIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_ARIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC03D, name: "TLS_RSA_WITH_ARIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::ARIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC03E, name: "TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::ARIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC03F, name: "TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::ARIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC040, name: "TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::ARIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC041, name: "TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::ARIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC042, name: "TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::ARIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC043, name: "TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::ARIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC044, name: "TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::ARIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC045, name: "TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::ARIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_ARIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC046, name: "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::ARIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_ARIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC047, name: "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::ARIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC048, name: "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::ARIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC049, name: "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::ARIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC04A, name: "TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::ECDH_ECDSA), encryption: TLSEncryption::ARIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC04B, name: "TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::ECDH_ECDSA), encryption: TLSEncryption::ARIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC04C, name: "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_RSA), encryption: TLSEncryption::ARIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC04D, name: "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::ECDHE_RSA), encryption: TLSEncryption::ARIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC04E, name: "TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::ECDH_RSA), encryption: TLSEncryption::ARIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC04F, name: "TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::ECDH_RSA), encryption: TLSEncryption::ARIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_ARIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC050, name: "TLS_RSA_WITH_ARIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::ARIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_ARIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC051, name: "TLS_RSA_WITH_ARIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::ARIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC052, name: "TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::ARIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC053, name: "TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::ARIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC054, name: "TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::ARIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC055, name: "TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::ARIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC056, name: "TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::ARIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC057, name: "TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::ARIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC058, name: "TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::ARIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC059, name: "TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::ARIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_ARIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC05A, name: "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::ARIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_ARIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC05B, name: "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::ARIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC05C, name: "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::ARIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC05D, name: "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::ARIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC05E, name: "TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::ECDH_ECDSA), encryption: TLSEncryption::ARIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC05F, name: "TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::ECDH_ECDSA), encryption: TLSEncryption::ARIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC060, name: "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_RSA), encryption: TLSEncryption::ARIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC061, name: "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::ECDHE_RSA), encryption: TLSEncryption::ARIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC062, name: "TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::ECDH_RSA), encryption: TLSEncryption::ARIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC063, name: "TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::ECDH_RSA), encryption: TLSEncryption::ARIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_PSK_WITH_ARIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC064, name: "TLS_PSK_WITH_ARIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::ARIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_PSK_WITH_ARIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC065, name: "TLS_PSK_WITH_ARIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::ARIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC066, name: "TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::ARIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC067, name: "TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::ARIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC068, name: "TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::ARIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC069, name: "TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::ARIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_PSK_WITH_ARIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC06A, name: "TLS_PSK_WITH_ARIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::ARIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_PSK_WITH_ARIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC06B, name: "TLS_PSK_WITH_ARIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::ARIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC06C, name: "TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::ARIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC06D, name: "TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::ARIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC06E, name: "TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::ARIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC06F, name: "TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::ARIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC070, name: "TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_PSK), encryption: TLSEncryption::ARIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC071, name: "TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::ECDHE_PSK), encryption: TLSEncryption::ARIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC072, name: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC073, name: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC074, name: "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::ECDH_ECDSA), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC075, name: "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::ECDH_ECDSA), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC076, name: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_RSA), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC077, name: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::ECDHE_RSA), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC078, name: "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::ECDH_RSA), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC079, name: "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::ECDH_RSA), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC07A, name: "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::CAMELLIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC07B, name: "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::CAMELLIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC07C, name: "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::CAMELLIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC07D, name: "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::CAMELLIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC07E, name: "TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::CAMELLIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC07F, name: "TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::DH_RSA), encryption: TLSEncryption::CAMELLIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC080, name: "TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::CAMELLIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC081, name: "TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::DHE_DSS), encryption: TLSEncryption::CAMELLIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC082, name: "TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::CAMELLIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC083, name: "TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::DH_DSS), encryption: TLSEncryption::CAMELLIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC084, name: "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::CAMELLIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC085, name: "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::DH_anon), encryption: TLSEncryption::CAMELLIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC086, name: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::CAMELLIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC087, name: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::CAMELLIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC088, name: "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::ECDH_ECDSA), encryption: TLSEncryption::CAMELLIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC089, name: "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::ECDH_ECDSA), encryption: TLSEncryption::CAMELLIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC08A, name: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_RSA), encryption: TLSEncryption::CAMELLIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC08B, name: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::ECDHE_RSA), encryption: TLSEncryption::CAMELLIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC08C, name: "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::ECDH_RSA), encryption: TLSEncryption::CAMELLIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC08D, name: "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::ECDH_RSA), encryption: TLSEncryption::CAMELLIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC08E, name: "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::CAMELLIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC08F, name: "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::CAMELLIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC090, name: "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::CAMELLIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC091, name: "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::CAMELLIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC092, name: "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::CAMELLIA_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC093, name: "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::CAMELLIA_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC094, name: "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC095, name: "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC096, name: "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC097, name: "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC098, name: "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC099, name: "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 => TLSCipherSpecification { number: 0xC09A, name: "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_PSK), encryption: TLSEncryption::CAMELLIA_128_CBC, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 => TLSCipherSpecification { number: 0xC09B, name: "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", key_exchange: Some(TLSKeyExchange::ECDHE_PSK), encryption: TLSEncryption::CAMELLIA_256_CBC, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_RSA_WITH_AES_128_CCM => TLSCipherSpecification { number: 0xC09C, name: "TLS_RSA_WITH_AES_128_CCM", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::AES_128_CCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_AES_256_CCM => TLSCipherSpecification { number: 0xC09D, name: "TLS_RSA_WITH_AES_256_CCM", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::AES_256_CCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_AES_128_CCM => TLSCipherSpecification { number: 0xC09E, name: "TLS_DHE_RSA_WITH_AES_128_CCM", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::AES_128_CCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_AES_256_CCM => TLSCipherSpecification { number: 0xC09F, name: "TLS_DHE_RSA_WITH_AES_256_CCM", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::AES_256_CCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_AES_128_CCM_8 => TLSCipherSpecification { number: 0xC0A0, name: "TLS_RSA_WITH_AES_128_CCM_8", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::AES_128_CCM_8, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_WITH_AES_256_CCM_8 => TLSCipherSpecification { number: 0xC0A1, name: "TLS_RSA_WITH_AES_256_CCM_8", key_exchange: Some(TLSKeyExchange::RSA), encryption: TLSEncryption::AES_256_CCM_8, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_AES_128_CCM_8 => TLSCipherSpecification { number: 0xC0A2, name: "TLS_DHE_RSA_WITH_AES_128_CCM_8", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::AES_128_CCM_8, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_RSA_WITH_AES_256_CCM_8 => TLSCipherSpecification { number: 0xC0A3, name: "TLS_DHE_RSA_WITH_AES_256_CCM_8", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::AES_256_CCM_8, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_PSK_WITH_AES_128_CCM => TLSCipherSpecification { number: 0xC0A4, name: "TLS_PSK_WITH_AES_128_CCM", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::AES_128_CCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_PSK_WITH_AES_256_CCM => TLSCipherSpecification { number: 0xC0A5, name: "TLS_PSK_WITH_AES_256_CCM", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::AES_256_CCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_DHE_PSK_WITH_AES_128_CCM => TLSCipherSpecification { number: 0xC0A6, name: "TLS_DHE_PSK_WITH_AES_128_CCM", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::AES_128_CCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_DHE_PSK_WITH_AES_256_CCM => TLSCipherSpecification { number: 0xC0A7, name: "TLS_DHE_PSK_WITH_AES_256_CCM", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::AES_256_CCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_PSK_WITH_AES_128_CCM_8 => TLSCipherSpecification { number: 0xC0A8, name: "TLS_PSK_WITH_AES_128_CCM_8", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::AES_128_CCM_8, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_PSK_WITH_AES_256_CCM_8 => TLSCipherSpecification { number: 0xC0A9, name: "TLS_PSK_WITH_AES_256_CCM_8", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::AES_256_CCM_8, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_PSK_DHE_WITH_AES_128_CCM_8 => TLSCipherSpecification { number: 0xC0AA, name: "TLS_PSK_DHE_WITH_AES_128_CCM_8", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::AES_128_CCM_8, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_PSK_DHE_WITH_AES_256_CCM_8 => TLSCipherSpecification { number: 0xC0AB, name: "TLS_PSK_DHE_WITH_AES_256_CCM_8", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::AES_256_CCM_8, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_CCM => TLSCipherSpecification { number: 0xC0AC, name: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::AES_128_CCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_CCM => TLSCipherSpecification { number: 0xC0AD, name: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::AES_256_CCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 => TLSCipherSpecification { number: 0xC0AE, name: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::AES_128_CCM_8, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 => TLSCipherSpecification { number: 0xC0AF, name: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::AES_256_CCM_8, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECCPWD_WITH_AES_128_GCM_SHA256 => TLSCipherSpecification { number: 0xC0B0, name: "TLS_ECCPWD_WITH_AES_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::ECCPWD), encryption: TLSEncryption::AES_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2, TLSVersion::V1_3], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECCPWD_WITH_AES_256_GCM_SHA384 => TLSCipherSpecification { number: 0xC0B1, name: "TLS_ECCPWD_WITH_AES_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::ECCPWD), encryption: TLSEncryption::AES_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2, TLSVersion::V1_3], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECCPWD_WITH_AES_128_CCM_SHA256 => TLSCipherSpecification { number: 0xC0B2, name: "TLS_ECCPWD_WITH_AES_128_CCM_SHA256", key_exchange: Some(TLSKeyExchange::ECCPWD), encryption: TLSEncryption::AES_128_CCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2, TLSVersion::V1_3], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECCPWD_WITH_AES_256_CCM_SHA384 => TLSCipherSpecification { number: 0xC0B3, name: "TLS_ECCPWD_WITH_AES_256_CCM_SHA384", key_exchange: Some(TLSKeyExchange::ECCPWD), encryption: TLSEncryption::AES_256_CCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2, TLSVersion::V1_3], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_SHA256_SHA256 => TLSCipherSpecification { number: 0xC0B4, name: "TLS_SHA256_SHA256", key_exchange: None, encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA256), hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_3], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_SHA384_SHA384 => TLSCipherSpecification { number: 0xC0B5, name: "TLS_SHA384_SHA384", key_exchange: None, encryption: TLSEncryption::NULL, mac: Some(TLSMAC::HMAC_SHA384), hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_3], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC => TLSCipherSpecification { number: 0xC100, name: "TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC", key_exchange: Some(TLSKeyExchange::GOSTR341112_256), encryption: TLSEncryption::KUZNYECHIK_CTR_ACPKM, mac: Some(TLSMAC::OMAC_KUZNYECHIK), hash: Some(TLSHash::STREEBOG256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC => TLSCipherSpecification { number: 0xC101, name: "TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC", key_exchange: Some(TLSKeyExchange::GOSTR341112_256), encryption: TLSEncryption::MAGMA_CTR_ACPKM, mac: Some(TLSMAC::OMAC_MAGMA), hash: Some(TLSHash::STREEBOG256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_GOSTR341112_256_WITH_28147_CNT_IMIT => TLSCipherSpecification { number: 0xC102, name: "TLS_GOSTR341112_256_WITH_28147_CNT_IMIT", key_exchange: Some(TLSKeyExchange::GOSTR341112_256), encryption: TLSEncryption::GOST28147_CNT, mac: Some(TLSMAC::IMIT_GOST28147), hash: Some(TLSHash::STREEBOG256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L => TLSCipherSpecification { number: 0xC103, name: "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L", key_exchange: None, encryption: TLSEncryption::KUZNYECHIK_MGM_L, mac: None, hash: Some(TLSHash::STREEBOG256), versions: &[TLSVersion::V1_3], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_GOSTR341112_256_WITH_MAGMA_MGM_L => TLSCipherSpecification { number: 0xC104, name: "TLS_GOSTR341112_256_WITH_MAGMA_MGM_L", key_exchange: None, encryption: TLSEncryption::MAGMA_MGM_L, mac: None, hash: Some(TLSHash::STREEBOG256), versions: &[TLSVersion::V1_3], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S => TLSCipherSpecification { number: 0xC105, name: "TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S", key_exchange: None, encryption: TLSEncryption::KUZNYECHIK_MGM_S, mac: None, hash: Some(TLSHash::STREEBOG256), versions: &[TLSVersion::V1_3], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_GOSTR341112_256_WITH_MAGMA_MGM_S => TLSCipherSpecification { number: 0xC106, name: "TLS_GOSTR341112_256_WITH_MAGMA_MGM_S", key_exchange: None, encryption: TLSEncryption::MAGMA_MGM_S, mac: None, hash: Some(TLSHash::STREEBOG256), versions: &[TLSVersion::V1_3], export: false, signaling: false, datagram: false, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => TLSCipherSpecification { number: 0xCCA8, name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_RSA), encryption: TLSEncryption::CHACHA20_POLY1305, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Recommended },
            Self::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => TLSCipherSpecification { number: 0xCCA9, name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_ECDSA), encryption: TLSEncryption::CHACHA20_POLY1305, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Recommended },
            Self::TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => TLSCipherSpecification { number: 0xCCAA, name: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", key_exchange: Some(TLSKeyExchange::DHE_RSA), encryption: TLSEncryption::CHACHA20_POLY1305, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 => TLSCipherSpecification { number: 0xCCAB, name: "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256", key_exchange: Some(TLSKeyExchange::PSK), encryption: TLSEncryption::CHACHA20_POLY1305, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => TLSCipherSpecification { number: 0xCCAC, name: "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_PSK), encryption: TLSEncryption::CHACHA20_POLY1305, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Recommended },
            Self::TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 => TLSCipherSpecification { number: 0xCCAD, name: "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256", key_exchange: Some(TLSKeyExchange::DHE_PSK), encryption: TLSEncryption::CHACHA20_POLY1305, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 => TLSCipherSpecification { number: 0xCCAE, name: "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256", key_exchange: Some(TLSKeyExchange::RSA_PSK), encryption: TLSEncryption::CHACHA20_POLY1305, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Discouraged },
            Self::TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 => TLSCipherSpecification { number: 0xD001, name: "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_PSK), encryption: TLSEncryption::AES_128_GCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Recommended },
            Self::TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384 => TLSCipherSpecification { number: 0xD002, name: "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384", key_exchange: Some(TLSKeyExchange::ECDHE_PSK), encryption: TLSEncryption::AES_256_GCM, mac: None, hash: Some(TLSHash::SHA384), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Recommended },
            Self::TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256 => TLSCipherSpecification { number: 0xD003, name: "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_PSK), encryption: TLSEncryption::AES_128_CCM_8, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::NotRecommended },
            Self::TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256 => TLSCipherSpecification { number: 0xD005, name: "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256", key_exchange: Some(TLSKeyExchange::ECDHE_PSK), encryption: TLSEncryption::AES_128_CCM, mac: None, hash: Some(TLSHash::SHA256), versions: &[TLSVersion::V1_2], export: false, signaling: false, datagram: true, recommendation: TLSRecommendation::Recommended },
        }
    }

    pub fn number(&self) -> u16 {
        self.specification().number
    }

    pub fn from_number(number: u16) -> Option<Self> {
        Self::ALL.iter().copied().find(|cipher| cipher.number() == number)
    }

    pub fn versions(&self) -> &'static [TLSVersion] {
        self.specification().versions
    }

    pub fn key_exchange(&self) -> Option<TLSKeyExchange> {
        self.specification().key_exchange
    }

    pub fn encryption(&self) -> TLSEncryption {
        self.specification().encryption
    }

    pub fn mac(&self) -> Option<TLSMAC> {
        self.specification().mac
    }

    pub fn hash(&self, version: TLSVersion) -> Option<TLSHash> {
        let specification = self.specification();
        if !specification.versions.contains(&version) {
            return None;
        }
        match version {
            TLSVersion::V1_0 | TLSVersion::V1_1 => specification.key_exchange.map(|_| TLSHash::MD5_SHA1),
            TLSVersion::V1_2 | TLSVersion::V1_3 => specification.hash,
        }
    }

    pub fn export(&self) -> bool {
        self.specification().export
    }

    pub fn signaling(&self) -> bool {
        self.specification().signaling
    }

    pub fn datagram(&self) -> bool {
        self.specification().datagram
    }

    pub fn recommendation(&self) -> TLSRecommendation {
        self.specification().recommendation
    }

    pub fn key_size(&self) -> usize {
        self.encryption().key_size()
    }

    pub fn nonce_size(&self) -> usize {
        self.encryption().nonce_size()
    }

    pub fn tag_size(&self) -> usize {
        self.encryption().tag_size()
    }

    pub fn as_str(&self) -> &'static str {
        self.specification().name
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|cipher| cipher.as_str() == name)
    }
}

impl fmt::Display for TLSCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TLSSignatureSchemeSpecification {
    pub number: u16,
    pub name: &'static str,
    pub recommendation: TLSRecommendation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSSignatureScheme {
    RSA_PKCS1_SHA1,
    ECDSA_SHA1,
    RSA_PKCS1_SHA256,
    ECDSA_SECP256R1_SHA256,
    RSA_PKCS1_SHA256_LEGACY,
    RSA_PKCS1_SHA384,
    ECDSA_SECP384R1_SHA384,
    RSA_PKCS1_SHA384_LEGACY,
    RSA_PKCS1_SHA512,
    ECDSA_SECP521R1_SHA512,
    RSA_PKCS1_SHA512_LEGACY,
    ECCSI_SHA256,
    ISO_IBS1,
    ISO_IBS2,
    ISO_CHINESE_IBS,
    SM2SIG_SM3,
    GOSTR34102012_256A,
    GOSTR34102012_256B,
    GOSTR34102012_256C,
    GOSTR34102012_256D,
    GOSTR34102012_512A,
    GOSTR34102012_512B,
    GOSTR34102012_512C,
    RSA_PSS_RSAE_SHA256,
    RSA_PSS_RSAE_SHA384,
    RSA_PSS_RSAE_SHA512,
    ED25519,
    ED448,
    RSA_PSS_PSS_SHA256,
    RSA_PSS_PSS_SHA384,
    RSA_PSS_PSS_SHA512,
    ECDSA_BRAINPOOLP256R1TLS13_SHA256,
    ECDSA_BRAINPOOLP384R1TLS13_SHA384,
    ECDSA_BRAINPOOLP512R1TLS13_SHA512,
    MLDSA44,
    MLDSA65,
    MLDSA87,
    SLHDSA_SHA2_128S,
    SLHDSA_SHA2_128F,
    SLHDSA_SHA2_192S,
    SLHDSA_SHA2_192F,
    SLHDSA_SHA2_256S,
    SLHDSA_SHA2_256F,
    SLHDSA_SHAKE_128S,
    SLHDSA_SHAKE_128F,
    SLHDSA_SHAKE_192S,
    SLHDSA_SHAKE_192F,
    SLHDSA_SHAKE_256S,
    SLHDSA_SHAKE_256F,
}

impl TLSSignatureScheme {
    pub const ALL: [Self; 49] = [
        Self::RSA_PKCS1_SHA1,
        Self::ECDSA_SHA1,
        Self::RSA_PKCS1_SHA256,
        Self::ECDSA_SECP256R1_SHA256,
        Self::RSA_PKCS1_SHA256_LEGACY,
        Self::RSA_PKCS1_SHA384,
        Self::ECDSA_SECP384R1_SHA384,
        Self::RSA_PKCS1_SHA384_LEGACY,
        Self::RSA_PKCS1_SHA512,
        Self::ECDSA_SECP521R1_SHA512,
        Self::RSA_PKCS1_SHA512_LEGACY,
        Self::ECCSI_SHA256,
        Self::ISO_IBS1,
        Self::ISO_IBS2,
        Self::ISO_CHINESE_IBS,
        Self::SM2SIG_SM3,
        Self::GOSTR34102012_256A,
        Self::GOSTR34102012_256B,
        Self::GOSTR34102012_256C,
        Self::GOSTR34102012_256D,
        Self::GOSTR34102012_512A,
        Self::GOSTR34102012_512B,
        Self::GOSTR34102012_512C,
        Self::RSA_PSS_RSAE_SHA256,
        Self::RSA_PSS_RSAE_SHA384,
        Self::RSA_PSS_RSAE_SHA512,
        Self::ED25519,
        Self::ED448,
        Self::RSA_PSS_PSS_SHA256,
        Self::RSA_PSS_PSS_SHA384,
        Self::RSA_PSS_PSS_SHA512,
        Self::ECDSA_BRAINPOOLP256R1TLS13_SHA256,
        Self::ECDSA_BRAINPOOLP384R1TLS13_SHA384,
        Self::ECDSA_BRAINPOOLP512R1TLS13_SHA512,
        Self::MLDSA44,
        Self::MLDSA65,
        Self::MLDSA87,
        Self::SLHDSA_SHA2_128S,
        Self::SLHDSA_SHA2_128F,
        Self::SLHDSA_SHA2_192S,
        Self::SLHDSA_SHA2_192F,
        Self::SLHDSA_SHA2_256S,
        Self::SLHDSA_SHA2_256F,
        Self::SLHDSA_SHAKE_128S,
        Self::SLHDSA_SHAKE_128F,
        Self::SLHDSA_SHAKE_192S,
        Self::SLHDSA_SHAKE_192F,
        Self::SLHDSA_SHAKE_256S,
        Self::SLHDSA_SHAKE_256F,
    ];

    pub fn specification(&self) -> TLSSignatureSchemeSpecification {
        match self {
            Self::RSA_PKCS1_SHA1 => TLSSignatureSchemeSpecification { number: 0x0201, name: "rsa_pkcs1_sha1", recommendation: TLSRecommendation::NotRecommended },
            Self::ECDSA_SHA1 => TLSSignatureSchemeSpecification { number: 0x0203, name: "ecdsa_sha1", recommendation: TLSRecommendation::NotRecommended },
            Self::RSA_PKCS1_SHA256 => TLSSignatureSchemeSpecification { number: 0x0401, name: "rsa_pkcs1_sha256", recommendation: TLSRecommendation::Recommended },
            Self::ECDSA_SECP256R1_SHA256 => TLSSignatureSchemeSpecification { number: 0x0403, name: "ecdsa_secp256r1_sha256", recommendation: TLSRecommendation::Recommended },
            Self::RSA_PKCS1_SHA256_LEGACY => TLSSignatureSchemeSpecification { number: 0x0420, name: "rsa_pkcs1_sha256_legacy", recommendation: TLSRecommendation::NotRecommended },
            Self::RSA_PKCS1_SHA384 => TLSSignatureSchemeSpecification { number: 0x0501, name: "rsa_pkcs1_sha384", recommendation: TLSRecommendation::Recommended },
            Self::ECDSA_SECP384R1_SHA384 => TLSSignatureSchemeSpecification { number: 0x0503, name: "ecdsa_secp384r1_sha384", recommendation: TLSRecommendation::Recommended },
            Self::RSA_PKCS1_SHA384_LEGACY => TLSSignatureSchemeSpecification { number: 0x0520, name: "rsa_pkcs1_sha384_legacy", recommendation: TLSRecommendation::NotRecommended },
            Self::RSA_PKCS1_SHA512 => TLSSignatureSchemeSpecification { number: 0x0601, name: "rsa_pkcs1_sha512", recommendation: TLSRecommendation::Recommended },
            Self::ECDSA_SECP521R1_SHA512 => TLSSignatureSchemeSpecification { number: 0x0603, name: "ecdsa_secp521r1_sha512", recommendation: TLSRecommendation::Recommended },
            Self::RSA_PKCS1_SHA512_LEGACY => TLSSignatureSchemeSpecification { number: 0x0620, name: "rsa_pkcs1_sha512_legacy", recommendation: TLSRecommendation::NotRecommended },
            Self::ECCSI_SHA256 => TLSSignatureSchemeSpecification { number: 0x0704, name: "eccsi_sha256", recommendation: TLSRecommendation::NotRecommended },
            Self::ISO_IBS1 => TLSSignatureSchemeSpecification { number: 0x0705, name: "iso_ibs1", recommendation: TLSRecommendation::NotRecommended },
            Self::ISO_IBS2 => TLSSignatureSchemeSpecification { number: 0x0706, name: "iso_ibs2", recommendation: TLSRecommendation::NotRecommended },
            Self::ISO_CHINESE_IBS => TLSSignatureSchemeSpecification { number: 0x0707, name: "iso_chinese_ibs", recommendation: TLSRecommendation::NotRecommended },
            Self::SM2SIG_SM3 => TLSSignatureSchemeSpecification { number: 0x0708, name: "sm2sig_sm3", recommendation: TLSRecommendation::NotRecommended },
            Self::GOSTR34102012_256A => TLSSignatureSchemeSpecification { number: 0x0709, name: "gostr34102012_256a", recommendation: TLSRecommendation::NotRecommended },
            Self::GOSTR34102012_256B => TLSSignatureSchemeSpecification { number: 0x070A, name: "gostr34102012_256b", recommendation: TLSRecommendation::NotRecommended },
            Self::GOSTR34102012_256C => TLSSignatureSchemeSpecification { number: 0x070B, name: "gostr34102012_256c", recommendation: TLSRecommendation::NotRecommended },
            Self::GOSTR34102012_256D => TLSSignatureSchemeSpecification { number: 0x070C, name: "gostr34102012_256d", recommendation: TLSRecommendation::NotRecommended },
            Self::GOSTR34102012_512A => TLSSignatureSchemeSpecification { number: 0x070D, name: "gostr34102012_512a", recommendation: TLSRecommendation::NotRecommended },
            Self::GOSTR34102012_512B => TLSSignatureSchemeSpecification { number: 0x070E, name: "gostr34102012_512b", recommendation: TLSRecommendation::NotRecommended },
            Self::GOSTR34102012_512C => TLSSignatureSchemeSpecification { number: 0x070F, name: "gostr34102012_512c", recommendation: TLSRecommendation::NotRecommended },
            Self::RSA_PSS_RSAE_SHA256 => TLSSignatureSchemeSpecification { number: 0x0804, name: "rsa_pss_rsae_sha256", recommendation: TLSRecommendation::Recommended },
            Self::RSA_PSS_RSAE_SHA384 => TLSSignatureSchemeSpecification { number: 0x0805, name: "rsa_pss_rsae_sha384", recommendation: TLSRecommendation::Recommended },
            Self::RSA_PSS_RSAE_SHA512 => TLSSignatureSchemeSpecification { number: 0x0806, name: "rsa_pss_rsae_sha512", recommendation: TLSRecommendation::Recommended },
            Self::ED25519 => TLSSignatureSchemeSpecification { number: 0x0807, name: "ed25519", recommendation: TLSRecommendation::Recommended },
            Self::ED448 => TLSSignatureSchemeSpecification { number: 0x0808, name: "ed448", recommendation: TLSRecommendation::Recommended },
            Self::RSA_PSS_PSS_SHA256 => TLSSignatureSchemeSpecification { number: 0x0809, name: "rsa_pss_pss_sha256", recommendation: TLSRecommendation::Recommended },
            Self::RSA_PSS_PSS_SHA384 => TLSSignatureSchemeSpecification { number: 0x080A, name: "rsa_pss_pss_sha384", recommendation: TLSRecommendation::Recommended },
            Self::RSA_PSS_PSS_SHA512 => TLSSignatureSchemeSpecification { number: 0x080B, name: "rsa_pss_pss_sha512", recommendation: TLSRecommendation::Recommended },
            Self::ECDSA_BRAINPOOLP256R1TLS13_SHA256 => TLSSignatureSchemeSpecification { number: 0x081A, name: "ecdsa_brainpoolP256r1tls13_sha256", recommendation: TLSRecommendation::NotRecommended },
            Self::ECDSA_BRAINPOOLP384R1TLS13_SHA384 => TLSSignatureSchemeSpecification { number: 0x081B, name: "ecdsa_brainpoolP384r1tls13_sha384", recommendation: TLSRecommendation::NotRecommended },
            Self::ECDSA_BRAINPOOLP512R1TLS13_SHA512 => TLSSignatureSchemeSpecification { number: 0x081C, name: "ecdsa_brainpoolP512r1tls13_sha512", recommendation: TLSRecommendation::NotRecommended },
            Self::MLDSA44 => TLSSignatureSchemeSpecification { number: 0x0904, name: "mldsa44", recommendation: TLSRecommendation::NotRecommended },
            Self::MLDSA65 => TLSSignatureSchemeSpecification { number: 0x0905, name: "mldsa65", recommendation: TLSRecommendation::NotRecommended },
            Self::MLDSA87 => TLSSignatureSchemeSpecification { number: 0x0906, name: "mldsa87", recommendation: TLSRecommendation::NotRecommended },
            Self::SLHDSA_SHA2_128S => TLSSignatureSchemeSpecification { number: 0x0911, name: "slhdsa_sha2_128s", recommendation: TLSRecommendation::NotRecommended },
            Self::SLHDSA_SHA2_128F => TLSSignatureSchemeSpecification { number: 0x0912, name: "slhdsa_sha2_128f", recommendation: TLSRecommendation::NotRecommended },
            Self::SLHDSA_SHA2_192S => TLSSignatureSchemeSpecification { number: 0x0913, name: "slhdsa_sha2_192s", recommendation: TLSRecommendation::NotRecommended },
            Self::SLHDSA_SHA2_192F => TLSSignatureSchemeSpecification { number: 0x0914, name: "slhdsa_sha2_192f", recommendation: TLSRecommendation::NotRecommended },
            Self::SLHDSA_SHA2_256S => TLSSignatureSchemeSpecification { number: 0x0915, name: "slhdsa_sha2_256s", recommendation: TLSRecommendation::NotRecommended },
            Self::SLHDSA_SHA2_256F => TLSSignatureSchemeSpecification { number: 0x0916, name: "slhdsa_sha2_256f", recommendation: TLSRecommendation::NotRecommended },
            Self::SLHDSA_SHAKE_128S => TLSSignatureSchemeSpecification { number: 0x0917, name: "slhdsa_shake_128s", recommendation: TLSRecommendation::NotRecommended },
            Self::SLHDSA_SHAKE_128F => TLSSignatureSchemeSpecification { number: 0x0918, name: "slhdsa_shake_128f", recommendation: TLSRecommendation::NotRecommended },
            Self::SLHDSA_SHAKE_192S => TLSSignatureSchemeSpecification { number: 0x0919, name: "slhdsa_shake_192s", recommendation: TLSRecommendation::NotRecommended },
            Self::SLHDSA_SHAKE_192F => TLSSignatureSchemeSpecification { number: 0x091A, name: "slhdsa_shake_192f", recommendation: TLSRecommendation::NotRecommended },
            Self::SLHDSA_SHAKE_256S => TLSSignatureSchemeSpecification { number: 0x091B, name: "slhdsa_shake_256s", recommendation: TLSRecommendation::NotRecommended },
            Self::SLHDSA_SHAKE_256F => TLSSignatureSchemeSpecification { number: 0x091C, name: "slhdsa_shake_256f", recommendation: TLSRecommendation::NotRecommended },
        }
    }

    pub fn number(&self) -> u16 {
        self.specification().number
    }

    pub fn from_number(number: u16) -> Option<Self> {
        Self::ALL.iter().copied().find(|scheme| scheme.number() == number)
    }

    pub fn recommendation(&self) -> TLSRecommendation {
        self.specification().recommendation
    }

    pub fn post_quantum(&self) -> bool {
        matches!(self, Self::MLDSA44 | Self::MLDSA65 | Self::MLDSA87 | Self::SLHDSA_SHA2_128S | Self::SLHDSA_SHA2_128F | Self::SLHDSA_SHA2_192S | Self::SLHDSA_SHA2_192F | Self::SLHDSA_SHA2_256S | Self::SLHDSA_SHA2_256F | Self::SLHDSA_SHAKE_128S | Self::SLHDSA_SHAKE_128F | Self::SLHDSA_SHAKE_192S | Self::SLHDSA_SHAKE_192F | Self::SLHDSA_SHAKE_256S | Self::SLHDSA_SHAKE_256F)
    }

    pub fn as_str(&self) -> &'static str {
        self.specification().name
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|scheme| scheme.as_str() == name)
    }
}

impl fmt::Display for TLSSignatureScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSSignatureAlgorithm {
    ANONYMOUS,
    RSA,
    DSA,
    ECDSA,
    ED25519,
    ED448,
    GOSTR34102012_256,
    GOSTR34102012_512,
}

impl TLSSignatureAlgorithm {
    pub const ALL: [Self; 8] = [Self::ANONYMOUS, Self::RSA, Self::DSA, Self::ECDSA, Self::ED25519, Self::ED448, Self::GOSTR34102012_256, Self::GOSTR34102012_512];

    pub fn number(&self) -> u8 {
        match self {
            Self::ANONYMOUS => 0,
            Self::RSA => 1,
            Self::DSA => 2,
            Self::ECDSA => 3,
            Self::ED25519 => 7,
            Self::ED448 => 8,
            Self::GOSTR34102012_256 => 64,
            Self::GOSTR34102012_512 => 65,
        }
    }

    pub fn from_number(number: u8) -> Option<Self> {
        Self::ALL.iter().copied().find(|algorithm| algorithm.number() == number)
    }

    pub fn datagram(&self) -> bool {
        match self {
            Self::ANONYMOUS | Self::RSA | Self::DSA | Self::ECDSA | Self::ED25519 | Self::ED448 | Self::GOSTR34102012_256 | Self::GOSTR34102012_512 => true,
        }
    }

    pub fn recommendation(&self) -> TLSRecommendation {
        match self {
            Self::RSA | Self::ECDSA | Self::ED25519 | Self::ED448 => TLSRecommendation::Recommended,
            Self::ANONYMOUS | Self::DSA | Self::GOSTR34102012_256 | Self::GOSTR34102012_512 => TLSRecommendation::NotRecommended,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ANONYMOUS => "anonymous",
            Self::RSA => "rsa",
            Self::DSA => "dsa",
            Self::ECDSA => "ecdsa",
            Self::ED25519 => "ed25519",
            Self::ED448 => "ed448",
            Self::GOSTR34102012_256 => "gostr34102012_256",
            Self::GOSTR34102012_512 => "gostr34102012_512",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|algorithm| algorithm.as_str() == name)
    }
}

impl fmt::Display for TLSSignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TLSHashAlgorithm {
    NONE,
    MD5,
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    INTRINSIC,
}

impl TLSHashAlgorithm {
    pub const ALL: [Self; 8] = [Self::NONE, Self::MD5, Self::SHA1, Self::SHA224, Self::SHA256, Self::SHA384, Self::SHA512, Self::INTRINSIC];

    pub fn number(&self) -> u8 {
        match self {
            Self::NONE => 0,
            Self::MD5 => 1,
            Self::SHA1 => 2,
            Self::SHA224 => 3,
            Self::SHA256 => 4,
            Self::SHA384 => 5,
            Self::SHA512 => 6,
            Self::INTRINSIC => 8,
        }
    }

    pub fn from_number(number: u8) -> Option<Self> {
        Self::ALL.iter().copied().find(|algorithm| algorithm.number() == number)
    }

    pub fn datagram(&self) -> bool {
        match self {
            Self::NONE | Self::MD5 | Self::SHA1 | Self::SHA224 | Self::SHA256 | Self::SHA384 | Self::SHA512 | Self::INTRINSIC => true,
        }
    }

    pub fn recommendation(&self) -> TLSRecommendation {
        match self {
            Self::NONE | Self::SHA256 | Self::SHA384 | Self::SHA512 | Self::INTRINSIC => TLSRecommendation::Recommended,
            Self::MD5 | Self::SHA1 | Self::SHA224 => TLSRecommendation::Discouraged,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NONE => "none",
            Self::MD5 => "md5",
            Self::SHA1 => "sha1",
            Self::SHA224 => "sha224",
            Self::SHA256 => "sha256",
            Self::SHA384 => "sha384",
            Self::SHA512 => "sha512",
            Self::INTRINSIC => "Intrinsic",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|algorithm| algorithm.as_str() == name)
    }
}

impl fmt::Display for TLSHashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TLSExtension {
    ServerName(String),
    SupportedVersions(Vec<TLSVersion>),
    SupportedGroups(Vec<TLSGroup>),
    SignatureAlgorithms(Vec<TLSSignatureScheme>),
    ApplicationLayerProtocolNegotiation(Vec<String>),
    KeyShare(Vec<(TLSGroup, Vec<u8>)>),
    PreSharedKey(Vec<u8>),
    EarlyData,
    SessionTicket(Vec<u8>),
    EncryptedClientHello(Vec<u8>),
    QUICTransportParameters(Vec<u8>),
    Unknown { kind: u16, data: Vec<u8> },
}

impl TLSExtension {
    pub fn kind(&self) -> u16 {
        todo!()
    }

    pub fn allowed(&self, version: TLSVersion) -> bool {
        todo!()
    }

    pub fn encode(&self) -> Vec<u8> {
        todo!()
    }

    pub fn decode(kind: u16, data: &[u8]) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TLSLimits {
    pub max_record_size: u32,
    pub max_handshake_size: u32,
    pub max_extension_size: u32,
    pub max_extension_count: u16,
    pub max_certificate_size: u32,
    pub max_certificate_chain_length: u8,
    pub max_early_data_size: u32,

    pub max_connection_count: u64,
    pub max_session_count: u32,
    pub max_records_per_key: u64,
    pub max_retry_count: u8,

    pub handshake_timeout: f64,
    pub read_timeout: f64,
    pub write_timeout: f64,
    pub close_timeout: f64,
    pub session_lifetime: f64,
}

impl Default for TLSLimits {
    fn default() -> Self {
        Self {
            max_record_size: 16 * 1024,
            max_handshake_size: 64 * 1024,
            max_extension_size: 16 * 1024,
            max_extension_count: 64,
            max_certificate_size: 64 * 1024,
            max_certificate_chain_length: 10,
            max_early_data_size: 16 * 1024,

            max_connection_count: 1024,
            max_session_count: 4096,
            max_records_per_key: 1 << 24,
            max_retry_count: 1,

            handshake_timeout: 10.0,
            read_timeout: 30.0,
            write_timeout: 30.0,
            close_timeout: 5.0,
            session_lifetime: 86400.0,
        }
    }
}
