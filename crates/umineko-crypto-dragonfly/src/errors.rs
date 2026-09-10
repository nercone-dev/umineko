use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DragonflyError {
    Group,
    Password,
    Element,
    Key,
    Encoding,
    Seed,
}

impl fmt::Display for DragonflyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl core::error::Error for DragonflyError {}
