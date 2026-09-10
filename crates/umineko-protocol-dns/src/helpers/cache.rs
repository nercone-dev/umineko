use alloc::vec::Vec;
use crate::types::{DNSName, DNSType, DNSClass, DNSRecord, DNSResponseCode, DNSLimits};

#[derive(Debug, Clone, PartialEq)]
pub struct DNSCacheEntry {
    pub question: (DNSName, DNSType, DNSClass),
    pub records: Vec<DNSRecord>,
    pub code: DNSResponseCode,
    pub elapsed: f64,
    pub lifetime: u32,
}

impl DNSCacheEntry {
    pub fn expired(&self) -> bool {
        todo!()
    }

    pub fn remaining(&self) -> u32 {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DNSCache {
    entries: Vec<DNSCacheEntry>,
    limits: DNSLimits,
}

impl DNSCache {
    pub fn new(limits: DNSLimits) -> Self {
        todo!()
    }

    pub fn insert(&mut self, entry: DNSCacheEntry) {
        todo!()
    }

    pub fn get(&self, name: &DNSName, kind: DNSType, class: DNSClass) -> Option<&DNSCacheEntry> {
        todo!()
    }

    pub fn remove(&mut self, name: &DNSName) {
        todo!()
    }

    pub fn expire(&mut self, elapsed: f64) -> usize {
        todo!()
    }

    pub fn clear(&mut self) {
        todo!()
    }

    pub fn len(&self) -> usize {
        todo!()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
