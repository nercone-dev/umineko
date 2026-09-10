use alloc::vec::Vec;
use crate::errors::KerberosError;
use crate::types::{KerberosPrincipal, KerberosEncryptionType};
use crate::helpers::key::KerberosKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosKeytabEntry {
    pub principal: KerberosPrincipal,
    pub timestamp: u32,
    pub version: u32,
    pub key: KerberosKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KerberosKeytab {
    entries: Vec<KerberosKeytabEntry>,
}

impl KerberosKeytab {
    pub const FORMAT_VERSION: u16 = 0x0502;

    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    pub fn entries(&self) -> &[KerberosKeytabEntry] {
        &self.entries
    }

    pub fn insert(&mut self, entry: KerberosKeytabEntry) {
        self.entries.push(entry);
    }

    pub fn remove(&mut self, principal: &KerberosPrincipal) -> usize {
        let count = self.entries.len();
        self.entries.retain(|entry| !entry.principal.matches(principal));
        count - self.entries.len()
    }

    pub fn find(&self, principal: &KerberosPrincipal, version: Option<u32>, encryption: KerberosEncryptionType) -> Option<&KerberosKeytabEntry> {
        self.entries.iter().filter(|entry| entry.principal.matches(principal) && entry.key.encryption() == encryption && version.is_none_or(|version| entry.version == version)).max_by_key(|entry| entry.version)
    }

    pub fn encode(&self) -> Result<Vec<u8>, KerberosError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<Self, KerberosError> {
        todo!()
    }
}
