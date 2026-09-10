use crate::errors::TLSError;
use crate::types::TLSCipher;

use umineko_crypto_hmac::HMACHash;
use umineko_crypto_kdftree::KDFTree;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TLSTree {
    constants: [u64; 3],
}

impl TLSTree {
    pub const LABELS: [&'static [u8]; 3] = [b"level1", b"level2", b"level3"];
    pub const KEY_SIZE: usize = 32;

    pub fn new(constants: [u64; 3]) -> Self {
        Self { constants }
    }

    pub fn from_cipher(cipher: TLSCipher) -> Option<Self> {
        match cipher {
            TLSCipher::TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC => Some(Self::new([0xFFFFFFFF00000000, 0xFFFFFFFFFFF80000, 0xFFFFFFFFFFFFFFC0])),
            TLSCipher::TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC => Some(Self::new([0xFFFFFFC000000000, 0xFFFFFFFFFE000000, 0xFFFFFFFFFFFFF000])),
            TLSCipher::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L => Some(Self::new([0xF800000000000000, 0xFFFFFFF000000000, 0xFFFFFFFFFFFFE000])),
            TLSCipher::TLS_GOSTR341112_256_WITH_MAGMA_MGM_L => Some(Self::new([0xFFE0000000000000, 0xFFFFFFFFC0000000, 0xFFFFFFFFFFFFFF80])),
            TLSCipher::TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S => Some(Self::new([0xFFFFFFFFE0000000, 0xFFFFFFFFFFFF0000, 0xFFFFFFFFFFFFFFF8])),
            TLSCipher::TLS_GOSTR341112_256_WITH_MAGMA_MGM_S => Some(Self::new([0xFFFFFFFFFC000000, 0xFFFFFFFFFFFFE000, 0xFFFFFFFFFFFFFFFF])),
            _ => None,
        }
    }

    pub fn constants(&self) -> [u64; 3] {
        self.constants
    }

    pub fn derive(&self, root: &[u8; 32], sequence: u64) -> Result<[u8; 32], TLSError> {
        let kdf = KDFTree::new(HMACHash::Streebog256, 1)?;
        let mut key = *root;
        for (label, constant) in Self::LABELS.into_iter().zip(self.constants) {
            let mut next = [0; Self::KEY_SIZE];
            kdf.derive(&key, label, &(sequence & constant).to_be_bytes(), &mut next)?;
            key = next;
        }
        Ok(key)
    }
}
