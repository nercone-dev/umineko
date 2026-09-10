use alloc::{vec::Vec, string::String, string::ToString};
use crate::errors::HTTPError;
use crate::types::HTTPBody;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HTTPCompression {
    Auto,      // 利用可能な圧縮方式から自動で選択。優先順位は Zstandard > Brotli > Gzip > Deflate
    Zstandard,
    Brotli,
    Gzip,
    Deflate,
    Unknown(String),
}

impl HTTPCompression {
    pub fn compress(&self, body: HTTPBody, encodings: Option<Vec<HTTPCompression>>) -> Result<HTTPBody, HTTPError> {
        todo!()
    }

    pub fn decompress(&self, body: HTTPBody, max: u64) -> Result<HTTPBody, HTTPError> {
        todo!()
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Auto => "identity",
            Self::Zstandard => "zstd",
            Self::Brotli => "br",
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
            Self::Unknown(name) => name,
        }
    }

    pub fn from_name(name: &str) -> Self {
        match name {
            "zstd"    => HTTPCompression::Zstandard,
            "br"      => HTTPCompression::Brotli,
            "gzip"    => HTTPCompression::Gzip,
            "deflate" => HTTPCompression::Deflate,
            _ => HTTPCompression::Unknown(name.to_string())
        }
    }

    pub fn select(accepted: &[Self]) -> Option<Self> {
        todo!()
    }

    pub fn decode_accepted(header: &str) -> Vec<Self> {
        todo!()
    }
}
