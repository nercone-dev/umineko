use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ARPError {
    Header,
    Type,
    Length,
    Truncated,
    Limit,
    Unresolved,
    Transport,
    Timeout,
}

impl fmt::Display for ARPError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for ARPError {}
