use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HuffmanError {
    /// The stream holds a code no tree assigns.
    Symbol,
    /// The code lengths describe no prefix code.
    Lengths,
    /// The stream ends inside a code.
    Truncated,
    /// The output would grow past its limit.
    Limit,
}

impl HuffmanError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Symbol => "unknown symbol",
            Self::Lengths => "invalid code lengths",
            Self::Truncated => "truncated stream",
            Self::Limit => "limit exceeded",
        }
    }
}

impl fmt::Display for HuffmanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::error::Error for HuffmanError {}
