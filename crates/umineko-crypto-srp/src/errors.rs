use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SRPError {
    Group,
    Key,
    Length,
    Seed,
}

impl fmt::Display for SRPError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for SRPError {}
