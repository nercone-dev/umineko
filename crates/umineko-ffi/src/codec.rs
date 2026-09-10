use crate::types::umineko_buffer_t;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum umineko_codec_t {
    UMINEKO_CODEC_BASE16 = 0,
    UMINEKO_CODEC_BASE32 = 1,
    UMINEKO_CODEC_BASE58 = 2,
    UMINEKO_CODEC_BASE64 = 3,
    UMINEKO_CODEC_BASE85 = 4,
    UMINEKO_CODEC_DEFLATE = 5,
    UMINEKO_CODEC_GZIP = 6,
    UMINEKO_CODEC_BROTLI = 7,
    UMINEKO_CODEC_ZSTANDARD = 8,
    UMINEKO_CODEC_LZ4 = 9,
    UMINEKO_CODEC_LZMA = 10,
    UMINEKO_CODEC_RLE = 11,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum umineko_codec_error_t {
    UMINEKO_CODEC_OK = 0,
    UMINEKO_CODEC_FORMAT = 1,
    UMINEKO_CODEC_CHECKSUM = 2,
    UMINEKO_CODEC_LIMIT = 3,
    UMINEKO_CODEC_TRUNCATED = 4,
}

impl umineko_codec_t {
    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_codec_encode(codec: umineko_codec_t, data: *const u8, length: usize, out: *mut umineko_buffer_t) -> umineko_codec_error_t {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_codec_decode(codec: umineko_codec_t, data: *const u8, length: usize, limit: usize, out: *mut umineko_buffer_t) -> umineko_codec_error_t {
        todo!()
    }
}
