use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NTPVersion {
    V3,
    V4,
}

impl NTPVersion {
    pub fn number(&self) -> u8 {
        match self {
            Self::V3 => 3,
            Self::V4 => 4,
        }
    }

    pub fn from_number(number: u8) -> Option<Self> {
        match number {
            3 => Some(Self::V3),
            4 => Some(Self::V4),
            _ => None,
        }
    }

    pub fn extensions(&self) -> bool {
        matches!(self, Self::V4)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V3 => "NTPv3",
            Self::V4 => "NTPv4",
        }
    }
}

impl fmt::Display for NTPVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NTPMode {
    SymmetricActive,
    SymmetricPassive,
    Client,
    Server,
    Broadcast,
    Control,
    Unknown(u8),
}

impl NTPMode {
    pub fn number(&self) -> u8 {
        todo!()
    }

    pub fn from_number(number: u8) -> Self {
        todo!()
    }

    pub fn peer(&self) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NTPStratum(pub u8);

impl NTPStratum {
    pub const UNSPECIFIED: Self = Self(0);
    pub const PRIMARY: Self = Self(1);
    pub const UNSYNCHRONIZED: Self = Self(16);

    pub fn usable(&self) -> bool {
        (1..16).contains(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NTPLeapIndicator {
    None,
    AddSecond,
    DeleteSecond,
    Unsynchronized,
}

impl NTPLeapIndicator {
    pub fn number(&self) -> u8 {
        todo!()
    }

    pub fn from_number(number: u8) -> Self {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NTPTimestamp {
    pub seconds: u32,
    pub fraction: u32,
}

impl NTPTimestamp {
    pub const ZERO: Self = Self { seconds: 0, fraction: 0 };
    pub const ERA_SECONDS: u64 = 1 << 32;
    pub const UNIX_OFFSET: u64 = 2_208_988_800;

    pub fn from_seconds(seconds: f64) -> Self {
        todo!()
    }

    pub fn to_seconds(&self) -> f64 {
        todo!()
    }

    pub fn difference(&self, other: Self) -> f64 {
        todo!()
    }

    pub fn encode(&self) -> [u8; 8] {
        todo!()
    }

    pub fn decode(data: &[u8; 8]) -> Self {
        todo!()
    }
}

impl fmt::Display for NTPTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct NTPLimits {
    pub max_packet_size: u16,
    pub max_extension_size: u16,
    pub max_extension_count: u8,

    pub max_connection_count: u64,
    pub max_sample_count: u8,
    pub max_retry_count: u8,

    pub max_offset: f64,
    pub max_round_trip_time: f64,
    pub max_stratum: u8,

    pub query_timeout: f64,
    pub read_timeout: f64,
    pub write_timeout: f64,
    pub min_poll_interval: f64,
}

impl Default for NTPLimits {
    fn default() -> Self {
        Self {
            max_packet_size: 1024,
            max_extension_size: 512,
            max_extension_count: 8,

            max_connection_count: 1024,
            max_sample_count: 8,
            max_retry_count: 3,

            max_offset: 1000.0,
            max_round_trip_time: 1.0,
            max_stratum: 15,

            query_timeout: 5.0,
            read_timeout: 5.0,
            write_timeout: 5.0,
            min_poll_interval: 16.0,
        }
    }
}
