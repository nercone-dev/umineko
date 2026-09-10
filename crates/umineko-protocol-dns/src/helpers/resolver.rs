use alloc::vec::Vec;
use core::future::poll_fn;
use crate::errors::DNSError;
use crate::types::{DNSName, DNSType, DNSClass, DNSRecord, DNSLimits};
use crate::protocol::base::DNSTransport;
use crate::helpers::cache::DNSCache;
use crate::provider::{DNSProviderRequest, DNSProviders};

use umineko_helpers::provider::{ProviderBackend, ProviderOpening};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DNSResolverMode {
    Recursive,
    Iterative,
    CacheOnly,
}

#[derive(Debug, Clone, PartialEq)]
pub struct DNSResolver {
    mode: DNSResolverMode,
    transports: Vec<DNSTransport>,
    servers: Vec<alloc::string::String>,
    cache: DNSCache,
    limits: DNSLimits,
}

impl DNSResolver {
    pub fn new(mode: DNSResolverMode, servers: Vec<alloc::string::String>, limits: DNSLimits) -> Self {
        todo!()
    }

    pub fn mode(&self) -> DNSResolverMode {
        self.mode
    }

    pub async fn resolve(&mut self, name: &DNSName, kind: DNSType, class: DNSClass) -> Result<Vec<DNSRecord>, DNSError> {
        let request = DNSProviderRequest { name, kind, class, mode: self.mode, servers: &self.servers, limits: &self.limits };
        match DNSProviders::open(&request)? {
            Some(ProviderOpening { provider, handle }) => {
                let backend = ProviderBackend::Handle { provider: provider.clone(), handle };
                let records = poll_fn(|cx| provider.poll_resolve(handle, cx)).await?;
                drop(backend);
                Ok(records)
            }
            None => todo!(),
        }
    }

    pub async fn resolve_address(&mut self, name: &DNSName) -> Result<Vec<DNSRecord>, DNSError> {
        let mut records = self.resolve(name, DNSType::AAAA, DNSClass::IN).await?;
        records.extend(self.resolve(name, DNSType::A, DNSClass::IN).await?);
        Ok(records)
    }

    pub async fn resolve_reverse(&mut self, address: &[u8]) -> Result<Vec<DNSRecord>, DNSError> {
        todo!()
    }

    pub fn cache(&self) -> &DNSCache {
        &self.cache
    }

    pub fn clear(&mut self) {
        todo!()
    }
}
