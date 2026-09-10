use core::ffi::{c_char, c_int};

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum umineko_status_t {
    UMINEKO_OK = 0,
    UMINEKO_ARGUMENT = 1,
    UMINEKO_MEMORY = 2,
    UMINEKO_UNAVAILABLE = 3,
    UMINEKO_FAILED = 4,
}

#[repr(C)]
#[derive(Debug)]
pub struct umineko_buffer_t {
    pub data: *mut u8,
    pub length: usize,
    pub capacity: usize,
}

impl umineko_buffer_t {
    #[unsafe(no_mangle)]
    pub extern "C" fn umineko_buffer_empty() -> umineko_buffer_t {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_buffer_free(buffer: *mut umineko_buffer_t) {
        todo!()
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct umineko_version_t {
    pub major: c_int,
    pub minor: c_int,
    pub patch: c_int,
}

impl umineko_version_t {
    #[unsafe(no_mangle)]
    pub extern "C" fn umineko_version() -> umineko_version_t {
        todo!()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn umineko_version_string() -> *const c_char {
        todo!()
    }
}
