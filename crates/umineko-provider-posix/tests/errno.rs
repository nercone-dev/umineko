#![cfg(unix)]

use std::io::{ErrorKind, Write};
use std::net::UdpSocket;
use std::os::unix::net::UnixStream;

use umineko_provider::{ProviderCategory, ProviderError};
use umineko_provider_posix::{POSIXErrno, POSIXProvider};

#[test]
fn errno_numbers_agree_with_the_platform_c_library() {
    let expected = [
        (POSIXErrno::EPERM, ErrorKind::PermissionDenied),
        (POSIXErrno::EACCES, ErrorKind::PermissionDenied),
        (POSIXErrno::EINTR, ErrorKind::Interrupted),
        (POSIXErrno::EAGAIN, ErrorKind::WouldBlock),
        (POSIXErrno::EWOULDBLOCK, ErrorKind::WouldBlock),
        (POSIXErrno::ENOMEM, ErrorKind::OutOfMemory),
        (POSIXErrno::EINVAL, ErrorKind::InvalidInput),
        (POSIXErrno::ENOSYS, ErrorKind::Unsupported),
        (POSIXErrno::ETIMEDOUT, ErrorKind::TimedOut),
        (POSIXErrno::EPIPE, ErrorKind::BrokenPipe),
        (POSIXErrno::ECONNRESET, ErrorKind::ConnectionReset),
    ];
    for (errno, kind) in expected {
        let number = errno.number().unwrap_or_else(|| panic!("{} has no number on this platform", errno.as_str()));
        assert_eq!(std::io::Error::from_raw_os_error(number).kind(), kind, "{}", errno.as_str());
    }
}

#[test]
fn a_nonblocking_receive_without_data_reports_eagain() {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_nonblocking(true).unwrap();
    let error = socket.recv(&mut [0; 1]).unwrap_err();
    let number = error.raw_os_error().unwrap();
    assert_eq!(POSIXErrno::from_number(number).map(|errno| errno.error()), Some(ProviderError::WouldBlock));
    assert_eq!(POSIXProvider::error(number), ProviderError::WouldBlock);
}

#[test]
fn writing_to_a_stream_without_a_peer_reports_epipe() {
    let (mut local, remote) = UnixStream::pair().unwrap();
    drop(remote);
    let error = (0..16).find_map(|_| local.write(&[0; 1024]).err()).expect("the write fails once the peer is gone");
    let number = error.raw_os_error().unwrap();
    assert_eq!(POSIXErrno::EPIPE.number(), Some(number));
    assert_eq!(POSIXProvider::error(number), ProviderError::Closed);
}

#[test]
fn errno_names_and_numbers_are_symmetric() {
    for errno in POSIXErrno::ALL {
        assert_eq!(POSIXErrno::from_name(errno.as_str()), Some(errno));
        if let Some(number) = errno.number() {
            let decoded = POSIXErrno::from_number(number).unwrap();
            assert_eq!(decoded.number(), Some(number), "{}", errno.as_str());
            assert_eq!(decoded.error(), errno.error(), "{}", errno.as_str());
        }
    }
    for (index, (errno, number)) in POSIXErrno::table().iter().enumerate() {
        for (other, value) in &POSIXErrno::table()[index + 1..] {
            assert!(errno != other, "{} appears twice", errno.as_str());
            if number == value {
                assert_eq!(errno.error(), other.error(), "{} and {} share {number}", errno.as_str(), other.as_str());
            }
        }
    }
    assert_eq!(POSIXErrno::from_number(0), None);
    assert_eq!(POSIXProvider::error(0), ProviderError::System(0));
}

#[test]
fn errno_classes_follow_their_posix_descriptions() {
    let expected = [
        (POSIXErrno::EPERM, ProviderError::Permission),
        (POSIXErrno::EACCES, ProviderError::Permission),
        (POSIXErrno::EINTR, ProviderError::Interrupted),
        (POSIXErrno::EAGAIN, ProviderError::WouldBlock),
        (POSIXErrno::EWOULDBLOCK, ProviderError::WouldBlock),
        (POSIXErrno::ENOMEM, ProviderError::Exhausted),
        (POSIXErrno::ENFILE, ProviderError::Exhausted),
        (POSIXErrno::EMFILE, ProviderError::Exhausted),
        (POSIXErrno::ENOBUFS, ProviderError::Exhausted),
        (POSIXErrno::EINVAL, ProviderError::Argument),
        (POSIXErrno::ENOSYS, ProviderError::Unsupported),
        (POSIXErrno::ENOTSUP, ProviderError::Unsupported),
        (POSIXErrno::EOPNOTSUPP, ProviderError::Unsupported),
        (POSIXErrno::ETIMEDOUT, ProviderError::Timeout),
        (POSIXErrno::EPIPE, ProviderError::Closed),
        (POSIXErrno::ECONNRESET, ProviderError::Closed),
        (POSIXErrno::ESHUTDOWN, ProviderError::Closed),
    ];
    for (errno, error) in expected {
        assert_eq!(errno.error(), error, "{}", errno.as_str());
    }
}

#[cfg(target_vendor = "apple")]
#[test]
fn darwin_errno_numbers_match_sys_errno_h() {
    let expected = [(POSIXErrno::EAGAIN, 35), (POSIXErrno::ENOBUFS, 55), (POSIXErrno::ENOSYS, 78), (POSIXErrno::ENOTSUP, 45), (POSIXErrno::EOPNOTSUPP, 102), (POSIXErrno::ETIMEDOUT, 60), (POSIXErrno::ECONNRESET, 54), (POSIXErrno::ESHUTDOWN, 58)];
    for (errno, number) in expected {
        assert_eq!(errno.number(), Some(number), "{}", errno.as_str());
    }
}

#[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm", target_arch = "aarch64", target_arch = "riscv32", target_arch = "riscv64")))]
#[test]
fn linux_errno_numbers_match_asm_generic_errno_h() {
    let expected = [(POSIXErrno::EAGAIN, 11), (POSIXErrno::ENOBUFS, 105), (POSIXErrno::ENOSYS, 38), (POSIXErrno::ENOTSUP, 95), (POSIXErrno::EOPNOTSUPP, 95), (POSIXErrno::ETIMEDOUT, 110), (POSIXErrno::ECONNRESET, 104), (POSIXErrno::ESHUTDOWN, 108)];
    for (errno, number) in expected {
        assert_eq!(errno.number(), Some(number), "{}", errno.as_str());
    }
}

#[cfg(target_os = "freebsd")]
#[test]
fn freebsd_errno_numbers_match_sys_errno_h() {
    let expected = [(POSIXErrno::EAGAIN, 35), (POSIXErrno::ENOBUFS, 55), (POSIXErrno::ENOSYS, 78), (POSIXErrno::ENOTSUP, 45), (POSIXErrno::EOPNOTSUPP, 45), (POSIXErrno::ETIMEDOUT, 60), (POSIXErrno::ECONNRESET, 54), (POSIXErrno::ESHUTDOWN, 58)];
    for (errno, number) in expected {
        assert_eq!(errno.number(), Some(number), "{}", errno.as_str());
    }
}

#[test]
fn the_posix_provider_covers_exactly_the_socket_categories() {
    for category in ProviderCategory::ALL {
        assert_eq!(POSIXProvider::provides(category), matches!(category, ProviderCategory::IP | ProviderCategory::ICMP | ProviderCategory::UDS | ProviderCategory::TCP | ProviderCategory::UDP), "{category}");
    }
}
