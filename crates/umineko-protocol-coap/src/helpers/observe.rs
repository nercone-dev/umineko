use alloc::{string::String, vec::Vec};
use crate::errors::CoAPError;
use crate::types::CoAPLimits;
use crate::protocol::message::CoAPToken;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoAPObservation {
    pub token: CoAPToken,
    pub path: String,
    pub sequence: u32,
    pub lifetime: u32,
}

impl CoAPObservation {
    pub fn fresher(&self, sequence: u32, elapsed: f64) -> bool {
        todo!()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CoAPObserver {
    observations: Vec<CoAPObservation>,
    limits: CoAPLimits,
}

impl CoAPObserver {
    pub fn new(limits: CoAPLimits) -> Self {
        todo!()
    }

    pub fn insert(&mut self, observation: CoAPObservation) -> Result<(), CoAPError> {
        todo!()
    }

    pub fn remove(&mut self, token: &CoAPToken) {
        todo!()
    }

    pub fn get(&self, token: &CoAPToken) -> Option<&CoAPObservation> {
        todo!()
    }

    pub fn watching(&self, path: &str) -> Vec<&CoAPObservation> {
        todo!()
    }

    pub fn expire(&mut self, elapsed: f64) -> usize {
        todo!()
    }

    pub fn clear(&mut self) {
        todo!()
    }
}
