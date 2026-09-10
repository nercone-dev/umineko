use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseError {
        Alphabet,
        Length,
        Padding,
}

impl fmt::Display for BaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for BaseError {}
