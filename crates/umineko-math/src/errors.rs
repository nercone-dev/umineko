use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MathError {
    Zero,
    Parity,
    Length,
    Encoding,
    Point,
    Curve,
    Range,
}

impl MathError {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Zero => "division by zero",
            Self::Parity => "even modulus",
            Self::Length => "invalid length",
            Self::Encoding => "invalid encoding",
            Self::Point => "invalid point",
            Self::Curve => "unknown curve",
            Self::Range => "value out of range",
        }
    }
}

impl fmt::Display for MathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl core::error::Error for MathError {}
