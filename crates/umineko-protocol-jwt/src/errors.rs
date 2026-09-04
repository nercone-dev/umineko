use alloc::string::String;
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JWTError {
    Syntax(String),
    Encoding(String),
    Algorithm(String),
    Signature,
    Decryption,
    Key(String),
    Expired,
    NotYetValid,
    Audience(String),
    MissingClaim(String),
    Limit,
}

impl fmt::Display for JWTError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for JWTError {}
