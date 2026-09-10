use alloc::{string::String, vec::Vec};
use crate::errors::POP3Error;
use crate::types::{POP3Capability, POP3State, POP3Limits};
use crate::helpers::uidl::POP3UniqueID;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct POP3Entry {
    pub number: u32,
    pub size: u64,
    pub unique: Option<POP3UniqueID>,
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct POP3Maildrop {
    entries: Vec<POP3Entry>,
}

impl POP3Maildrop {
    pub fn new() -> Self {
        todo!()
    }

    pub fn get(&self, number: u32) -> Result<&POP3Entry, POP3Error> {
        todo!()
    }

    pub fn delete(&mut self, number: u32) -> Result<(), POP3Error> {
        todo!()
    }

    pub fn reset(&mut self) {
        todo!()
    }

    pub fn commit(&mut self) -> usize {
        todo!()
    }

    pub fn stat(&self) -> (u32, u64) {
        todo!()
    }

    pub fn entries(&self) -> &[POP3Entry] {
        todo!()
    }
}

impl Default for POP3Maildrop {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct POP3Session {
    state: POP3State,
    capabilities: Vec<POP3Capability>,
    username: Option<String>,
    maildrop: POP3Maildrop,
    secure: bool,
    banner: Option<String>,
}

impl POP3Session {
    pub fn new() -> Self {
        todo!()
    }

    pub fn state(&self) -> POP3State {
        self.state
    }

    pub fn maildrop(&self) -> &POP3Maildrop {
        &self.maildrop
    }

    pub fn secure(&self) -> bool {
        self.secure
    }

    pub fn advance(&mut self, state: POP3State) -> Result<(), POP3Error> {
        todo!()
    }

    pub fn supports(&self, capability: &POP3Capability) -> bool {
        todo!()
    }

    pub fn validate(&self, limits: POP3Limits) -> Result<(), POP3Error> {
        todo!()
    }
}

impl Default for POP3Session {
    fn default() -> Self {
        Self::new()
    }
}
