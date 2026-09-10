use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ASN1Error {
    Tag,
    Length,
    Truncated,
    Canonical,
    Depth,
    ObjectIdentifier,
    Value,
}

impl fmt::Display for ASN1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for ASN1Error {}
