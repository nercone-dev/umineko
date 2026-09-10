#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GOSTMode {
    ECB,
    CBC,
    CFB,
    OFB,
    CTR,
    CTR_ACPKM,
    MGM,
}

impl GOSTMode {
    pub fn authenticated(&self) -> bool {
        matches!(self, Self::MGM)
    }

    pub fn padded(&self) -> bool {
        matches!(self, Self::ECB | Self::CBC)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ECB => "ECB",
            Self::CBC => "CBC",
            Self::CFB => "CFB",
            Self::OFB => "OFB",
            Self::CTR => "CTR",
            Self::CTR_ACPKM => "CTR-ACPKM",
            Self::MGM => "MGM",
        }
    }
}
