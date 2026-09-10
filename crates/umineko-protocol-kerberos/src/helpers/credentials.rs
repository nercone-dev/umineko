use alloc::vec::Vec;
use crate::errors::KerberosError;
use crate::types::KerberosPrincipal;
use crate::helpers::key::KerberosKey;
use crate::protocol::messages::KerberosTicket;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosCredentials {
    pub client: KerberosPrincipal,
    pub server: KerberosPrincipal,
    pub key: KerberosKey,
    pub ticket: KerberosTicket,
    pub flags: u32,
    pub authentication_time: u64,
    pub start_time: Option<u64>,
    pub end_time: u64,
    pub renew_until: Option<u64>,
}

impl KerberosCredentials {
    pub fn expired(&self, now: u64) -> bool {
        now >= self.end_time
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KerberosCredentialCache {
    credentials: Vec<KerberosCredentials>,
}

impl KerberosCredentialCache {
    pub fn new() -> Self {
        Self { credentials: Vec::new() }
    }

    pub fn credentials(&self) -> &[KerberosCredentials] {
        &self.credentials
    }

    pub fn insert(&mut self, credentials: KerberosCredentials) {
        self.credentials.retain(|existing| !existing.client.matches(&credentials.client) || !existing.server.matches(&credentials.server));
        self.credentials.push(credentials);
    }

    pub fn find(&self, client: &KerberosPrincipal, server: &KerberosPrincipal) -> Option<&KerberosCredentials> {
        self.credentials.iter().find(|credentials| credentials.client.matches(client) && credentials.server.matches(server))
    }

    pub fn remove_expired(&mut self, now: u64) -> usize {
        let count = self.credentials.len();
        self.credentials.retain(|credentials| !credentials.expired(now));
        count - self.credentials.len()
    }

    pub fn encode(&self) -> Result<Vec<u8>, KerberosError> {
        todo!()
    }

    pub fn decode(data: &[u8]) -> Result<Self, KerberosError> {
        todo!()
    }
}
