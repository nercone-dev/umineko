use core::ffi::c_char;
use crate::types::umineko_status_t;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum umineko_hash_algorithm_t {
    UMINEKO_HASH_MD5 = 0,
    UMINEKO_HASH_SHA1 = 1,
    UMINEKO_HASH_SHA2_256 = 2,
    UMINEKO_HASH_SHA2_512 = 3,
    UMINEKO_HASH_SHA3_256 = 4,
    UMINEKO_HASH_SHA3_512 = 5,
    UMINEKO_HASH_BLAKE2B = 6,
    UMINEKO_HASH_BLAKE3 = 7,
    UMINEKO_HASH_SM3 = 8,
}

impl umineko_hash_algorithm_t {
    #[unsafe(no_mangle)]
    pub extern "C" fn umineko_hash_digest_size(algorithm: umineko_hash_algorithm_t) -> usize {
        todo!()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn umineko_hash_name(algorithm: umineko_hash_algorithm_t) -> *const c_char {
        todo!()
    }
}

#[repr(C)]
pub struct umineko_hash_t {
    _private: [u8; 0],
}

impl umineko_hash_t {
    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_hash_new(algorithm: umineko_hash_algorithm_t, out: *mut *mut umineko_hash_t) -> umineko_status_t {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_hash_free(hash: *mut umineko_hash_t) {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_hash_update(hash: *mut umineko_hash_t, data: *const u8, length: usize) -> umineko_status_t {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_hash_finalize(hash: *mut umineko_hash_t, digest: *mut u8, length: usize) -> umineko_status_t {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_hash_digest(algorithm: umineko_hash_algorithm_t, data: *const u8, length: usize, digest: *mut u8, digest_length: usize) -> umineko_status_t {
        todo!()
    }
}
