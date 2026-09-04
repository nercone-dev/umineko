use alloc::sync::Arc;
use core::fmt;
use crate::provider::base::{Provider, ProviderHandle};

pub struct ProviderOpening<P: ?Sized + Provider> {
    pub provider: Arc<P>,
    pub handle: ProviderHandle,
}

impl<P: ?Sized + Provider> ProviderOpening<P> {
    pub fn new(provider: Arc<P>, handle: ProviderHandle) -> Self {
        Self { provider, handle }
    }

    pub fn backend(self) -> ProviderBackend<P> {
        ProviderBackend::Handle { provider: self.provider, handle: self.handle }
    }
}

impl<P: ?Sized + Provider> fmt::Debug for ProviderOpening<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderOpening").field("provider", &self.provider.name()).field("handle", &self.handle).finish()
    }
}

pub enum ProviderBackend<P: ?Sized + Provider> {
    Builtin,
    Handle { provider: Arc<P>, handle: ProviderHandle },
}

impl<P: ?Sized + Provider> ProviderBackend<P> {
    pub fn builtin(&self) -> bool {
        matches!(self, Self::Builtin)
    }

    pub fn provider(&self) -> Option<&Arc<P>> {
        match self {
            Self::Builtin => None,
            Self::Handle { provider, .. } => Some(provider),
        }
    }

    pub fn handle(&self) -> Option<ProviderHandle> {
        match self {
            Self::Builtin => None,
            Self::Handle { handle, .. } => Some(*handle),
        }
    }

    pub fn duplicate(&self, duplicate: impl FnOnce(&Arc<P>, ProviderHandle) -> ProviderHandle) -> Self {
        match self {
            Self::Builtin => Self::Builtin,
            Self::Handle { provider, handle } => Self::Handle { provider: provider.clone(), handle: duplicate(provider, *handle) },
        }
    }
}

impl<P: ?Sized + Provider> Drop for ProviderBackend<P> {
    fn drop(&mut self) {
        if let Self::Handle { provider, handle } = self {
            provider.release(*handle);
        }
    }
}

impl<P: ?Sized + Provider> fmt::Debug for ProviderBackend<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Builtin => f.write_str("Builtin"),
            Self::Handle { provider, handle } => f.debug_struct("Handle").field("provider", &provider.name()).field("handle", handle).finish(),
        }
    }
}
