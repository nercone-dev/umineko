//! Encodings and compression.

#![no_std]

#[cfg(feature = "base")]
pub use umineko_codec_base as base;
#[cfg(feature = "brotli")]
pub use umineko_codec_brotli as brotli;
#[cfg(feature = "deflate")]
pub use umineko_codec_deflate as deflate;
#[cfg(feature = "gzip")]
pub use umineko_codec_gzip as gzip;
#[cfg(feature = "huffman")]
pub use umineko_codec_huffman as huffman;
#[cfg(feature = "lz4")]
pub use umineko_codec_lz4 as lz4;
#[cfg(feature = "lz77")]
pub use umineko_codec_lz77 as lz77;
#[cfg(feature = "lz78")]
pub use umineko_codec_lz78 as lz78;
#[cfg(feature = "lzss")]
pub use umineko_codec_lzss as lzss;
#[cfg(feature = "lzma")]
pub use umineko_codec_lzma as lzma;
#[cfg(feature = "rle")]
pub use umineko_codec_rle as rle;
#[cfg(feature = "zstandard")]
pub use umineko_codec_zstandard as zstandard;
