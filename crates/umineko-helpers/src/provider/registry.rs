use alloc::{sync::Arc, vec::Vec};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::provider::base::{Provider, ProviderError, ProviderFallback, ProviderHandle, ProviderOrder, ProviderPolicy};
use crate::provider::backend::{ProviderBackend, ProviderOpening};

pub struct ProviderLock<'a> {
    flag: &'a AtomicBool,
}

impl<'a> ProviderLock<'a> {
    pub fn acquire(flag: &'a AtomicBool) -> Self {
        while flag.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        Self { flag }
    }
}

impl Drop for ProviderLock<'_> {
    fn drop(&mut self) {
        self.flag.store(false, Ordering::Release);
    }
}

pub struct ProviderEntry<P: ?Sized> {
    name: &'static str,
    priority: i32,
    enabled: bool,
    provider: Arc<P>,
}

impl<P: ?Sized + Provider> ProviderEntry<P> {
    pub fn new(provider: Arc<P>) -> Self {
        Self { name: provider.name(), priority: provider.priority(), enabled: true, provider }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn priority(&self) -> i32 {
        self.priority
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn provider(&self) -> &Arc<P> {
        &self.provider
    }
}

pub struct ProviderSelection<P: ?Sized> {
    candidates: Vec<Arc<P>>,
    builtin: bool,
    fallback: ProviderFallback,
}

impl<P: ?Sized + Provider> ProviderSelection<P> {
    pub fn new(candidates: Vec<Arc<P>>, builtin: bool, fallback: ProviderFallback) -> Self {
        Self { candidates, builtin, fallback }
    }

    pub fn candidates(&self) -> &[Arc<P>] {
        &self.candidates
    }

    pub fn builtin(&self) -> bool {
        self.builtin
    }

    pub fn fallback(&self) -> ProviderFallback {
        self.fallback
    }

    pub fn resolve<T>(self, mut operation: impl FnMut(&Arc<P>) -> Result<T, ProviderError>) -> Result<Option<T>, ProviderError> {
        let mut last = None;
        for provider in &self.candidates {
            match operation(provider) {
                Ok(value) => return Ok(Some(value)),
                Err(error) if self.fallback.continues(&error) => last = Some(error),
                Err(error) => return Err(error),
            }
        }
        match (self.builtin, last) {
            (true, _) => Ok(None),
            (false, Some(error)) => Err(error),
            (false, None) => Err(ProviderError::Unsupported),
        }
    }

    pub fn open(self, mut open: impl FnMut(&Arc<P>) -> Result<ProviderHandle, ProviderError>) -> Result<Option<ProviderOpening<P>>, ProviderError> {
        self.resolve(|provider| open(provider).map(|handle| ProviderOpening::new(provider.clone(), handle)))
    }

    /// Panics when the policy excludes the builtin implementation and every candidate failed.
    pub fn backend(self, open: impl FnMut(&Arc<P>) -> Result<ProviderHandle, ProviderError>) -> ProviderBackend<P> {
        match self.open(open).unwrap_or_else(|error| panic!("the provider policy excludes the builtin implementation and every provider failed: {error}")) {
            Some(opening) => opening.backend(),
            None => ProviderBackend::Builtin,
        }
    }

    /// Panics when the policy excludes the builtin implementation and every candidate failed.
    pub fn require<T>(self, operation: impl FnMut(&Arc<P>) -> Result<T, ProviderError>) -> Option<T> {
        self.resolve(operation).unwrap_or_else(|error| panic!("the provider policy excludes the builtin implementation and every provider failed: {error}"))
    }
}

pub struct ProviderRegistry<P: ?Sized + Provider> {
    lock: AtomicBool,
    count: AtomicUsize,
    explicit: AtomicBool,
    entries: UnsafeCell<Vec<ProviderEntry<P>>>,
    policy: UnsafeCell<ProviderPolicy>,
}

unsafe impl<P: ?Sized + Provider> Sync for ProviderRegistry<P> {}

impl<P: ?Sized + Provider> ProviderRegistry<P> {
    pub const fn new() -> Self {
        Self {
            lock: AtomicBool::new(false),
            count: AtomicUsize::new(0),
            explicit: AtomicBool::new(false),
            entries: UnsafeCell::new(Vec::new()),
            policy: UnsafeCell::new(ProviderPolicy::DEFAULT),
        }
    }

    pub fn lock(&self) -> ProviderLock<'_> {
        ProviderLock::acquire(&self.lock)
    }

    pub fn register(&self, provider: Arc<P>) -> Result<(), ProviderError> {
        let entry = ProviderEntry::new(provider);
        if entry.name() == ProviderPolicy::BUILTIN {
            return Err(ProviderError::Argument);
        }
        let _lock = self.lock();
        let entries = unsafe { &mut *self.entries.get() };
        if entries.iter().any(|existing| existing.name == entry.name) {
            return Err(ProviderError::Argument);
        }
        Self::place(entries, entry);
        self.count.store(entries.len(), Ordering::Relaxed);
        Ok(())
    }

    /// Puts one entry where the highest priority comes first and equal priorities keep their order.
    pub fn place(entries: &mut Vec<ProviderEntry<P>>, entry: ProviderEntry<P>) {
        let position = entries.iter().position(|existing| existing.priority < entry.priority);
        entries.insert(position.unwrap_or(entries.len()), entry);
    }

    pub fn unregister(&self, name: &str) -> bool {
        let removed = {
            let _lock = self.lock();
            let entries = unsafe { &mut *self.entries.get() };
            let removed = entries.iter().position(|entry| entry.name == name).map(|position| entries.remove(position));
            self.count.store(entries.len(), Ordering::Relaxed);
            removed
        };
        removed.is_some()
    }

    pub fn get(&self, name: &str) -> Option<Arc<P>> {
        let _lock = self.lock();
        let entries = unsafe { &*self.entries.get() };
        entries.iter().find(|entry| entry.name == name).map(|entry| entry.provider.clone())
    }

    pub fn names(&self) -> Vec<&'static str> {
        let _lock = self.lock();
        let entries = unsafe { &*self.entries.get() };
        entries.iter().map(|entry| entry.name).collect()
    }

    pub fn len(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn enabled(&self, name: &str) -> Option<bool> {
        let _lock = self.lock();
        let entries = unsafe { &*self.entries.get() };
        entries.iter().find(|entry| entry.name == name).map(|entry| entry.enabled)
    }

    pub fn set_enabled(&self, name: &str, enabled: bool) -> bool {
        let _lock = self.lock();
        let entries = unsafe { &mut *self.entries.get() };
        match entries.iter_mut().find(|entry| entry.name == name) {
            Some(entry) => {
                entry.enabled = enabled;
                true
            }
            None => false,
        }
    }

    pub fn priority(&self, name: &str) -> Option<i32> {
        let _lock = self.lock();
        let entries = unsafe { &*self.entries.get() };
        entries.iter().find(|entry| entry.name == name).map(|entry| entry.priority)
    }

    pub fn set_priority(&self, name: &str, priority: i32) -> bool {
        let _lock = self.lock();
        let entries = unsafe { &mut *self.entries.get() };
        match entries.iter().position(|entry| entry.name == name) {
            Some(position) => {
                let mut entry = entries.remove(position);
                entry.priority = priority;
                Self::place(entries, entry);
                true
            }
            None => false,
        }
    }

    pub fn policy(&self) -> ProviderPolicy {
        let _lock = self.lock();
        unsafe { &*self.policy.get() }.clone()
    }

    pub fn set_policy(&self, policy: ProviderPolicy) {
        let previous = {
            let _lock = self.lock();
            self.explicit.store(matches!(policy.order, ProviderOrder::Explicit(_)), Ordering::Relaxed);
            core::mem::replace(unsafe { &mut *self.policy.get() }, policy)
        };
        drop(previous);
    }

    pub fn select(&self, supports: impl Fn(&P) -> bool) -> ProviderSelection<P> {
        if self.count.load(Ordering::Relaxed) == 0 && !self.explicit.load(Ordering::Relaxed) {
            return ProviderSelection::new(Vec::new(), true, ProviderPolicy::DEFAULT.fallback);
        }
        let (candidates, builtin, fallback) = {
            let _lock = self.lock();
            let entries = unsafe { &*self.entries.get() };
            let policy = unsafe { &*self.policy.get() };
            let mut ordered = Vec::new();
            match &policy.order {
                ProviderOrder::Priority => {
                    ordered.extend(entries.iter().filter(|entry| entry.enabled && supports(&entry.provider)).map(|entry| entry.provider.clone()));
                    (ordered, true, policy.fallback)
                }
                ProviderOrder::Explicit(names) => {
                    let mut builtin = false;
                    for name in names {
                        if name == ProviderPolicy::BUILTIN {
                            builtin = true;
                            break;
                        }
                        if let Some(entry) = entries.iter().find(|entry| entry.enabled && entry.name == name && supports(&entry.provider)) {
                            ordered.push(entry.provider.clone());
                        }
                    }
                    (ordered, builtin, policy.fallback)
                }
            }
        };
        ProviderSelection::new(candidates, builtin, fallback)
    }
}

impl<P: ?Sized + Provider> Default for ProviderRegistry<P> {
    fn default() -> Self {
        Self::new()
    }
}
