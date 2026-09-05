use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseError {
    /// The text contains a symbol outside the alphabet.
    Alphabet,
    /// The text length cannot describe any byte sequence.
    Length,
    /// The padding is missing, misplaced or malformed.
    Padding,
}

impl BaseError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Alphabet => "symbol outside the alphabet",
            Self::Length => "invalid length",
            Self::Padding => "invalid padding",
        }
    }
}

impl fmt::Display for BaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::error::Error for BaseError {}
