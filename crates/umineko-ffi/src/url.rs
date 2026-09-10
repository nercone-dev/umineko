use core::ffi::{c_char, c_int};
use crate::types::{umineko_buffer_t, umineko_status_t};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum umineko_url_error_t {
    UMINEKO_URL_OK = 0,
    UMINEKO_URL_SCHEME = 1,
    UMINEKO_URL_HOST = 2,
    UMINEKO_URL_PORT = 3,
    UMINEKO_URL_ENCODING = 4,
    UMINEKO_URL_REFERENCE = 5,
}

#[repr(C)]
pub struct umineko_url_t {
    _private: [u8; 0],
}

impl umineko_url_t {
    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_url_parse(text: *const c_char, out: *mut *mut umineko_url_t) -> umineko_url_error_t {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_url_free(url: *mut umineko_url_t) {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_url_encode(url: *const umineko_url_t, out: *mut umineko_buffer_t) -> umineko_status_t {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_url_scheme(url: *const umineko_url_t) -> *const c_char {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_url_port(url: *const umineko_url_t) -> c_int {
        todo!()
    }
}
