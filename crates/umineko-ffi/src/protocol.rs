use core::ffi::c_char;
use crate::types::{umineko_buffer_t, umineko_status_t};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum umineko_http_error_t {
    UMINEKO_HTTP_OK = 0,
    UMINEKO_HTTP_VERSION = 1,
    UMINEKO_HTTP_STARTLINE = 2,
    UMINEKO_HTTP_HEADER = 3,
    UMINEKO_HTTP_BODY = 4,
    UMINEKO_HTTP_COMPRESSION = 5,
    UMINEKO_HTTP_LIMIT = 6,
    UMINEKO_HTTP_TARGET = 7,
    UMINEKO_HTTP_TLS = 8,
    UMINEKO_HTTP_TRANSPORT = 9,
    UMINEKO_HTTP_CLOSED = 10,
    UMINEKO_HTTP_TIMEOUT = 11,
}

#[repr(C)]
pub struct umineko_http_message_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct umineko_http_client_t {
    _private: [u8; 0],
}

impl umineko_http_client_t {
    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_http_client_new(out: *mut *mut umineko_http_client_t) -> umineko_status_t {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_http_client_free(client: *mut umineko_http_client_t) {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_http_client_fetch(client: *mut umineko_http_client_t, method: *const c_char, url: *const c_char, body: *const u8, body_length: usize, out: *mut *mut umineko_http_message_t) -> umineko_http_error_t {
        todo!()
    }
}

impl umineko_http_message_t {
    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_http_message_free(message: *mut umineko_http_message_t) {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_http_message_status(message: *const umineko_http_message_t) -> i32 {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_http_message_header(message: *const umineko_http_message_t, name: *const c_char) -> *const c_char {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_http_message_body(message: *const umineko_http_message_t, out: *mut umineko_buffer_t) -> umineko_http_error_t {
        todo!()
    }
}
