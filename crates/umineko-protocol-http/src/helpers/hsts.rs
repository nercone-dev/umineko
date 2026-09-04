use alloc::{string::String, vec::Vec};
use crate::errors::HTTPError;

use umineko_url::URL;

#[derive(Debug, Clone, PartialEq)]
pub struct HSTSPolicy {
    pub host: String,
    pub max_age: u64,
    pub include_subdomains: bool,
    pub elapsed: f64,
}

impl HSTSPolicy {
    pub fn decode(host: &str, header: &str) -> Result<Self, HTTPError> {
        todo!()
    }

    pub fn encode(&self) -> String {
        todo!()
    }

    pub fn matches(&self, host: &str) -> bool {
        todo!()
    }

    pub fn expired(&self) -> bool {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HSTSStore {
    policies: Vec<HSTSPolicy>,
}

impl HSTSStore {
    pub fn new() -> Self {
        todo!()
    }

    pub fn insert(&mut self, policy: HSTSPolicy) {
        todo!()
    }

    pub fn remove(&mut self, host: &str) {
        todo!()
    }

    pub fn get(&self, host: &str) -> Option<&HSTSPolicy> {
        todo!()
    }

    pub fn rewrite(&self, url: &URL) -> Option<URL> {
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

impl Default for HSTSStore {
    fn default() -> Self {
        Self::new()
    }
}
