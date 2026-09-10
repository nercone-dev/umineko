use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use umineko_helpers::provider::{Provider, ProviderBackend, ProviderCategory, ProviderError, ProviderFallback, ProviderHandle, ProviderOrder, ProviderPolicy, ProviderRegistry};

struct Fake {
    name: &'static str,
    priority: i32,
    supported: bool,
    failure: Option<ProviderError>,
    released: AtomicUsize,
}

impl Fake {
    fn new(name: &'static str, priority: i32) -> Arc<Self> {
        Arc::new(Self { name, priority, supported: true, failure: None, released: AtomicUsize::new(0) })
    }

    fn unsupported(name: &'static str) -> Arc<Self> {
        Arc::new(Self { name, priority: 0, supported: false, failure: None, released: AtomicUsize::new(0) })
    }

    fn failing(name: &'static str, failure: ProviderError) -> Arc<Self> {
        Arc::new(Self { name, priority: 0, supported: true, failure: Some(failure), released: AtomicUsize::new(0) })
    }

    fn open(&self) -> Result<ProviderHandle, ProviderError> {
        match self.failure {
            Some(failure) => Err(failure),
            None => Ok(ProviderHandle::new(ProviderCategory::Hash, 7)),
        }
    }
}

impl Provider for Fake {
    fn name(&self) -> &'static str {
        self.name
    }

    fn priority(&self) -> i32 {
        self.priority
    }

    fn release(&self, _handle: ProviderHandle) {
        self.released.fetch_add(1, Ordering::SeqCst);
    }
}

fn names(registry: &ProviderRegistry<Fake>) -> Vec<&'static str> {
    registry.select(|provider| provider.supported).candidates().iter().map(|provider| provider.name).collect()
}

#[test]
fn empty_registry_selects_only_the_builtin_implementation() {
    let registry: ProviderRegistry<Fake> = ProviderRegistry::new();
    assert!(registry.is_empty());
    let selection = registry.select(|_| true);
    assert!(selection.candidates().is_empty());
    assert!(selection.builtin());
    assert_eq!(selection.resolve(|_| Ok::<(), _>(())), Ok(None));
}

#[test]
fn registration_rejects_duplicates_and_the_reserved_name() {
    let registry: ProviderRegistry<Fake> = ProviderRegistry::new();
    assert_eq!(registry.register(Fake::new("a", 0)), Ok(()));
    assert_eq!(registry.register(Fake::new("a", 5)), Err(ProviderError::Argument));
    assert_eq!(registry.register(Fake::new(ProviderPolicy::BUILTIN, 0)), Err(ProviderError::Argument));
    assert_eq!(registry.names(), ["a"]);
    assert_eq!(registry.len(), 1);
}

#[test]
fn priority_order_is_descending_and_stable_for_ties() {
    let registry: ProviderRegistry<Fake> = ProviderRegistry::new();
    registry.register(Fake::new("low", -1)).unwrap();
    registry.register(Fake::new("first", 3)).unwrap();
    registry.register(Fake::new("second", 3)).unwrap();
    registry.register(Fake::new("high", 10)).unwrap();
    assert_eq!(names(&registry), ["high", "first", "second", "low"]);
    assert!(registry.select(|_| true).builtin());
}

#[test]
fn disabled_providers_are_skipped_until_enabled_again() {
    let registry: ProviderRegistry<Fake> = ProviderRegistry::new();
    registry.register(Fake::new("a", 1)).unwrap();
    registry.register(Fake::new("b", 0)).unwrap();
    assert!(registry.set_enabled("a", false));
    assert_eq!(registry.enabled("a"), Some(false));
    assert_eq!(names(&registry), ["b"]);
    assert!(registry.set_enabled("a", true));
    assert_eq!(names(&registry), ["a", "b"]);
    assert!(!registry.set_enabled("missing", true));
    assert_eq!(registry.enabled("missing"), None);
}

#[test]
fn set_priority_reorders_candidates() {
    let registry: ProviderRegistry<Fake> = ProviderRegistry::new();
    registry.register(Fake::new("a", 0)).unwrap();
    registry.register(Fake::new("b", 0)).unwrap();
    assert_eq!(names(&registry), ["a", "b"]);
    assert!(registry.set_priority("b", 1));
    assert_eq!(registry.priority("b"), Some(1));
    assert_eq!(names(&registry), ["b", "a"]);
    assert!(!registry.set_priority("missing", 1));
}

#[test]
fn explicit_order_follows_the_list_and_ignores_unknown_names() {
    let registry: ProviderRegistry<Fake> = ProviderRegistry::new();
    registry.register(Fake::new("a", 10)).unwrap();
    registry.register(Fake::new("b", 0)).unwrap();
    registry.set_policy(ProviderPolicy::explicit(&["b", "missing", "a"]));
    let selection = registry.select(|_| true);
    assert_eq!(selection.candidates().iter().map(|provider| provider.name).collect::<Vec<_>>(), ["b", "a"]);
    assert!(!selection.builtin());
}

#[test]
fn explicit_order_stops_at_the_builtin_name() {
    let registry: ProviderRegistry<Fake> = ProviderRegistry::new();
    registry.register(Fake::new("a", 0)).unwrap();
    registry.register(Fake::new("b", 0)).unwrap();
    registry.set_policy(ProviderPolicy::explicit(&["a", ProviderPolicy::BUILTIN, "b"]));
    let selection = registry.select(|_| true);
    assert_eq!(selection.candidates().iter().map(|provider| provider.name).collect::<Vec<_>>(), ["a"]);
    assert!(selection.builtin());
    registry.set_policy(ProviderPolicy::builtin());
    let selection = registry.select(|_| true);
    assert!(selection.candidates().is_empty());
    assert!(selection.builtin());
}

#[test]
fn explicit_policy_without_builtin_fails_on_an_empty_registry() {
    let registry: ProviderRegistry<Fake> = ProviderRegistry::new();
    registry.set_policy(ProviderPolicy::only("a"));
    assert_eq!(registry.select(|_| true).resolve(|_| Ok::<(), _>(())), Err(ProviderError::Unsupported));
}

#[test]
fn unsupported_requests_filter_candidates() {
    let registry: ProviderRegistry<Fake> = ProviderRegistry::new();
    registry.register(Fake::unsupported("a")).unwrap();
    registry.register(Fake::new("b", 0)).unwrap();
    assert_eq!(names(&registry), ["b"]);
}

#[test]
fn fallback_never_returns_the_first_failure() {
    let registry: ProviderRegistry<Fake> = ProviderRegistry::new();
    registry.register(Fake::failing("a", ProviderError::Unavailable)).unwrap();
    registry.register(Fake::new("b", -1)).unwrap();
    registry.set_policy(ProviderPolicy { order: ProviderOrder::Priority, fallback: ProviderFallback::Never });
    assert_eq!(registry.select(|_| true).resolve(|provider| provider.open()), Err(ProviderError::Unavailable));
}

#[test]
fn fallback_declined_continues_only_on_declined_errors() {
    let registry: ProviderRegistry<Fake> = ProviderRegistry::new();
    registry.register(Fake::failing("a", ProviderError::Unsupported)).unwrap();
    registry.register(Fake::new("b", -1)).unwrap();
    let handle = registry.select(|_| true).resolve(|provider| provider.open()).unwrap().unwrap();
    assert_eq!(handle, ProviderHandle::new(ProviderCategory::Hash, 7));

    let registry: ProviderRegistry<Fake> = ProviderRegistry::new();
    registry.register(Fake::failing("a", ProviderError::System(5))).unwrap();
    registry.register(Fake::new("b", -1)).unwrap();
    assert_eq!(registry.select(|_| true).resolve(|provider| provider.open()), Err(ProviderError::System(5)));
}

#[test]
fn fallback_any_continues_on_every_error_and_reaches_the_builtin_implementation() {
    let registry: ProviderRegistry<Fake> = ProviderRegistry::new();
    registry.register(Fake::failing("a", ProviderError::System(5))).unwrap();
    registry.register(Fake::failing("b", ProviderError::Timeout)).unwrap();
    registry.set_policy(ProviderPolicy { order: ProviderOrder::Priority, fallback: ProviderFallback::Any });
    assert_eq!(registry.select(|_| true).resolve(|provider| provider.open()), Ok(None));
    registry.set_policy(ProviderPolicy { order: ProviderOrder::Explicit(vec!["a".into(), "b".into()]), fallback: ProviderFallback::Any });
    assert_eq!(registry.select(|_| true).resolve(|provider| provider.open()), Err(ProviderError::Timeout));
}

#[test]
fn open_produces_a_handle_backend_that_is_released_on_drop() {
    let registry: ProviderRegistry<Fake> = ProviderRegistry::new();
    let provider = Fake::new("a", 0);
    registry.register(provider.clone()).unwrap();
    let opening = registry.select(|_| true).open(|provider| provider.open()).unwrap().unwrap();
    assert_eq!(opening.provider.name, "a");
    let backend = opening.backend();
    assert!(!backend.builtin());
    assert_eq!(backend.handle(), Some(ProviderHandle::new(ProviderCategory::Hash, 7)));
    assert_eq!(backend.provider().map(|provider| provider.name), Some("a"));
    let duplicate = backend.duplicate(|_, handle| ProviderHandle::new(handle.category, handle.value + 1));
    assert_eq!(duplicate.handle(), Some(ProviderHandle::new(ProviderCategory::Hash, 8)));
    drop(backend);
    assert_eq!(provider.released.load(Ordering::SeqCst), 1);
    drop(duplicate);
    assert_eq!(provider.released.load(Ordering::SeqCst), 2);
}

#[test]
fn builtin_backend_never_releases() {
    let registry: ProviderRegistry<Fake> = ProviderRegistry::new();
    assert!(registry.select(|_| true).open(|provider| provider.open()).unwrap().is_none());
    let backend = registry.select(|_| true).backend(|provider| provider.open());
    assert!(backend.builtin());
    assert!(matches!(backend, ProviderBackend::Builtin));
    assert_eq!(backend.handle(), None);
}

#[test]
#[should_panic]
fn backend_panics_when_the_policy_excludes_the_builtin_implementation() {
    let registry: ProviderRegistry<Fake> = ProviderRegistry::new();
    registry.register(Fake::failing("a", ProviderError::Unavailable)).unwrap();
    registry.set_policy(ProviderPolicy::only("a"));
    let _ = registry.select(|_| true).backend(|provider| provider.open());
}

#[test]
fn unregister_removes_the_provider() {
    let registry: ProviderRegistry<Fake> = ProviderRegistry::new();
    registry.register(Fake::new("a", 0)).unwrap();
    assert!(registry.get("a").is_some());
    assert!(registry.unregister("a"));
    assert!(!registry.unregister("a"));
    assert!(registry.get("a").is_none());
    assert!(registry.is_empty());
}

#[test]
fn policy_round_trips() {
    let registry: ProviderRegistry<Fake> = ProviderRegistry::new();
    assert_eq!(registry.policy(), ProviderPolicy::DEFAULT);
    let policy = ProviderPolicy { order: ProviderOrder::Explicit(vec!["a".into()]), fallback: ProviderFallback::Any };
    registry.set_policy(policy.clone());
    assert_eq!(registry.policy(), policy);
}
