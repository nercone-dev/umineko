#![cfg(target_os = "wasi")]

use std::io::ErrorKind;

use umineko_provider::ProviderError;
use umineko_provider_wasi::WASIProvider;

#[test]
fn wasi_errno_numbers_agree_with_the_platform_c_library() {
    let expected = [("acces", 2, ErrorKind::PermissionDenied), ("again", 6, ErrorKind::WouldBlock), ("connreset", 15, ErrorKind::ConnectionReset), ("intr", 27, ErrorKind::Interrupted), ("inval", 28, ErrorKind::InvalidInput), ("nomem", 48, ErrorKind::OutOfMemory), ("nosys", 52, ErrorKind::Unsupported), ("notdir", 54, ErrorKind::NotADirectory), ("notsup", 58, ErrorKind::Unsupported), ("perm", 63, ErrorKind::PermissionDenied), ("pipe", 64, ErrorKind::BrokenPipe), ("timedout", 73, ErrorKind::TimedOut)];
    for (name, number, kind) in expected {
        assert_eq!(std::io::Error::from_raw_os_error(number).kind(), kind, "{name}");
    }
}

#[test]
fn wasi_errno_classes_follow_their_posix_descriptions() {
    let expected = [("acces", 2, ProviderError::Permission), ("perm", 63, ProviderError::Permission), ("intr", 27, ProviderError::Interrupted), ("again", 6, ProviderError::WouldBlock), ("nomem", 48, ProviderError::Exhausted), ("nfile", 41, ProviderError::Exhausted), ("mfile", 33, ProviderError::Exhausted), ("nobufs", 42, ProviderError::Exhausted), ("inval", 28, ProviderError::Argument), ("nosys", 52, ProviderError::Unsupported), ("notsup", 58, ProviderError::Unsupported), ("timedout", 73, ProviderError::Timeout), ("pipe", 64, ProviderError::Closed), ("connreset", 15, ProviderError::Closed)];
    for (name, number, error) in expected {
        assert_eq!(WASIProvider::error(number), error, "{name}");
    }
}

#[test]
fn unclassified_wasi_errno_numbers_are_reported_as_system_errors() {
    let classified = [2, 6, 15, 27, 28, 33, 41, 42, 48, 52, 58, 63, 64, 73];
    for number in (0..=76).filter(|number| !classified.contains(number)) {
        assert_eq!(WASIProvider::error(number), ProviderError::System(number), "{number}");
    }
    assert_eq!(WASIProvider::error(54), ProviderError::System(54), "notdir");
    assert_eq!(WASIProvider::error(68), ProviderError::System(68), "range");
    assert_eq!(WASIProvider::error(-1), ProviderError::System(-1));
}
