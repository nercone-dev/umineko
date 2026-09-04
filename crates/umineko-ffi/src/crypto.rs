use crate::types::umineko_buffer_t;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum umineko_aead_t {
    UMINEKO_AEAD_AES128_GCM = 0,
    UMINEKO_AEAD_AES256_GCM = 1,
    UMINEKO_AEAD_CHACHA20_POLY1305 = 2,
    UMINEKO_AEAD_ASCON128 = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum umineko_kem_t {
    UMINEKO_KEM_X25519 = 0,
    UMINEKO_KEM_MLKEM768 = 1,
    UMINEKO_KEM_MLKEM1024 = 2,
    UMINEKO_KEM_X25519MLKEM768 = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum umineko_signature_t {
    UMINEKO_SIGNATURE_ED25519 = 0,
    UMINEKO_SIGNATURE_ECDSA_P256 = 1,
    UMINEKO_SIGNATURE_RSA_PSS = 2,
    UMINEKO_SIGNATURE_MLDSA65 = 3,
    UMINEKO_SIGNATURE_MLDSA87 = 4,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum umineko_crypto_error_t {
    UMINEKO_CRYPTO_OK = 0,
    UMINEKO_CRYPTO_KEY = 1,
    UMINEKO_CRYPTO_NONCE = 2,
    UMINEKO_CRYPTO_LENGTH = 3,
    UMINEKO_CRYPTO_AUTHENTICATION = 4,
    UMINEKO_CRYPTO_VERIFICATION = 5,
    UMINEKO_CRYPTO_SEED = 6,
}

impl umineko_aead_t {
    #[unsafe(no_mangle)]
    pub extern "C" fn umineko_aead_key_size(aead: umineko_aead_t) -> usize {
        todo!()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn umineko_aead_nonce_size(aead: umineko_aead_t) -> usize {
        todo!()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn umineko_aead_tag_size(aead: umineko_aead_t) -> usize {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_aead_encrypt(aead: umineko_aead_t, key: *const u8, key_length: usize, nonce: *const u8, nonce_length: usize, associated: *const u8, associated_length: usize, plaintext: *const u8, plaintext_length: usize, out: *mut umineko_buffer_t) -> umineko_crypto_error_t {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_aead_decrypt(aead: umineko_aead_t, key: *const u8, key_length: usize, nonce: *const u8, nonce_length: usize, associated: *const u8, associated_length: usize, ciphertext: *const u8, ciphertext_length: usize, out: *mut umineko_buffer_t) -> umineko_crypto_error_t {
        todo!()
    }
}

impl umineko_signature_t {
    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_signature_generate(signature: umineko_signature_t, seed: *const u8, seed_length: usize, private_out: *mut umineko_buffer_t, public_out: *mut umineko_buffer_t) -> umineko_crypto_error_t {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_signature_sign(signature: umineko_signature_t, key: *const u8, key_length: usize, message: *const u8, message_length: usize, out: *mut umineko_buffer_t) -> umineko_crypto_error_t {
        todo!()
    }

    ///
    ///
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn umineko_signature_verify(signature: umineko_signature_t, key: *const u8, key_length: usize, message: *const u8, message_length: usize, data: *const u8, data_length: usize) -> umineko_crypto_error_t {
        todo!()
    }
}
