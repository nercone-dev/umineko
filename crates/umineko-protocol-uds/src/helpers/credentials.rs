use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UDSCredentials {
    pub process: u32,
    pub user: u32,
    pub group: u32,
    pub groups: Vec<u32>,
}

impl UDSCredentials {
    pub fn privileged(&self) -> bool {
        self.user == 0
    }

    pub fn member_of(&self, group: u32) -> bool {
        todo!()
    }
}
