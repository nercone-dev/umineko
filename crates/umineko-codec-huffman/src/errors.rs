use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HuffmanError {
        Symbol,
        Lengths,
        Truncated,
        Limit,
}

impl fmt::Display for HuffmanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for HuffmanError {}
