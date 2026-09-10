use umineko_provider::ProviderError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum POSIXErrno {
    EPERM,
    EACCES,
    EINTR,
    EAGAIN,
    EWOULDBLOCK,
    ENOMEM,
    ENFILE,
    EMFILE,
    ENOBUFS,
    EINVAL,
    ENOSYS,
    ENOTSUP,
    EOPNOTSUPP,
    ETIMEDOUT,
    EPIPE,
    ECONNRESET,
    ESHUTDOWN,
}

impl POSIXErrno {
    pub const ALL: [Self; 17] = [Self::EPERM, Self::EACCES, Self::EINTR, Self::EAGAIN, Self::EWOULDBLOCK, Self::ENOMEM, Self::ENFILE, Self::EMFILE, Self::ENOBUFS, Self::EINVAL, Self::ENOSYS, Self::ENOTSUP, Self::EOPNOTSUPP, Self::ETIMEDOUT, Self::EPIPE, Self::ECONNRESET, Self::ESHUTDOWN];

    pub fn table() -> &'static [(Self, i32)] {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "l4re", all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64", target_arch = "arm", target_arch = "aarch64", target_arch = "csky", target_arch = "hexagon", target_arch = "loongarch64", target_arch = "m68k", target_arch = "powerpc", target_arch = "powerpc64", target_arch = "riscv32", target_arch = "riscv64", target_arch = "s390x", target_arch = "wasm32"))))]
        return &[(Self::EPERM, 1), (Self::EACCES, 13), (Self::EINTR, 4), (Self::EAGAIN, 11), (Self::EWOULDBLOCK, 11), (Self::ENOMEM, 12), (Self::ENFILE, 23), (Self::EMFILE, 24), (Self::ENOBUFS, 105), (Self::EINVAL, 22), (Self::ENOSYS, 38), (Self::ENOTSUP, 95), (Self::EOPNOTSUPP, 95), (Self::ETIMEDOUT, 110), (Self::EPIPE, 32), (Self::ECONNRESET, 104), (Self::ESHUTDOWN, 108)];
        #[cfg(all(target_os = "linux", any(target_arch = "mips", target_arch = "mips64", target_arch = "mips32r6", target_arch = "mips64r6")))]
        return &[(Self::EPERM, 1), (Self::EACCES, 13), (Self::EINTR, 4), (Self::EAGAIN, 11), (Self::EWOULDBLOCK, 11), (Self::ENOMEM, 12), (Self::ENFILE, 23), (Self::EMFILE, 24), (Self::ENOBUFS, 132), (Self::EINVAL, 22), (Self::ENOSYS, 89), (Self::ENOTSUP, 122), (Self::EOPNOTSUPP, 122), (Self::ETIMEDOUT, 145), (Self::EPIPE, 32), (Self::ECONNRESET, 131), (Self::ESHUTDOWN, 143)];
        #[cfg(all(target_os = "linux", any(target_arch = "sparc", target_arch = "sparc64")))]
        return &[(Self::EPERM, 1), (Self::EACCES, 13), (Self::EINTR, 4), (Self::EAGAIN, 11), (Self::EWOULDBLOCK, 11), (Self::ENOMEM, 12), (Self::ENFILE, 23), (Self::EMFILE, 24), (Self::ENOBUFS, 55), (Self::EINVAL, 22), (Self::ENOSYS, 90), (Self::ENOTSUP, 45), (Self::EOPNOTSUPP, 45), (Self::ETIMEDOUT, 60), (Self::EPIPE, 32), (Self::ECONNRESET, 54), (Self::ESHUTDOWN, 58)];
        #[cfg(target_vendor = "apple")]
        return &[(Self::EPERM, 1), (Self::EACCES, 13), (Self::EINTR, 4), (Self::EAGAIN, 35), (Self::EWOULDBLOCK, 35), (Self::ENOMEM, 12), (Self::ENFILE, 23), (Self::EMFILE, 24), (Self::ENOBUFS, 55), (Self::EINVAL, 22), (Self::ENOSYS, 78), (Self::ENOTSUP, 45), (Self::EOPNOTSUPP, 102), (Self::ETIMEDOUT, 60), (Self::EPIPE, 32), (Self::ECONNRESET, 54), (Self::ESHUTDOWN, 58)];
        #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
        return &[(Self::EPERM, 1), (Self::EACCES, 13), (Self::EINTR, 4), (Self::EAGAIN, 35), (Self::EWOULDBLOCK, 35), (Self::ENOMEM, 12), (Self::ENFILE, 23), (Self::EMFILE, 24), (Self::ENOBUFS, 55), (Self::EINVAL, 22), (Self::ENOSYS, 78), (Self::ENOTSUP, 45), (Self::EOPNOTSUPP, 45), (Self::ETIMEDOUT, 60), (Self::EPIPE, 32), (Self::ECONNRESET, 54), (Self::ESHUTDOWN, 58)];
        #[cfg(target_os = "netbsd")]
        return &[(Self::EPERM, 1), (Self::EACCES, 13), (Self::EINTR, 4), (Self::EAGAIN, 35), (Self::EWOULDBLOCK, 35), (Self::ENOMEM, 12), (Self::ENFILE, 23), (Self::EMFILE, 24), (Self::ENOBUFS, 55), (Self::EINVAL, 22), (Self::ENOSYS, 78), (Self::ENOTSUP, 86), (Self::EOPNOTSUPP, 45), (Self::ETIMEDOUT, 60), (Self::EPIPE, 32), (Self::ECONNRESET, 54), (Self::ESHUTDOWN, 58)];
        #[cfg(target_os = "openbsd")]
        return &[(Self::EPERM, 1), (Self::EACCES, 13), (Self::EINTR, 4), (Self::EAGAIN, 35), (Self::EWOULDBLOCK, 35), (Self::ENOMEM, 12), (Self::ENFILE, 23), (Self::EMFILE, 24), (Self::ENOBUFS, 55), (Self::EINVAL, 22), (Self::ENOSYS, 78), (Self::ENOTSUP, 91), (Self::EOPNOTSUPP, 45), (Self::ETIMEDOUT, 60), (Self::EPIPE, 32), (Self::ECONNRESET, 54), (Self::ESHUTDOWN, 58)];
        #[cfg(any(target_os = "solaris", target_os = "illumos"))]
        return &[(Self::EPERM, 1), (Self::EACCES, 13), (Self::EINTR, 4), (Self::EAGAIN, 11), (Self::EWOULDBLOCK, 11), (Self::ENOMEM, 12), (Self::ENFILE, 23), (Self::EMFILE, 24), (Self::ENOBUFS, 132), (Self::EINVAL, 22), (Self::ENOSYS, 89), (Self::ENOTSUP, 48), (Self::EOPNOTSUPP, 122), (Self::ETIMEDOUT, 145), (Self::EPIPE, 32), (Self::ECONNRESET, 131), (Self::ESHUTDOWN, 143)];
        #[cfg(target_os = "aix")]
        return &[(Self::EPERM, 1), (Self::EACCES, 13), (Self::EINTR, 4), (Self::EAGAIN, 11), (Self::EWOULDBLOCK, 11), (Self::ENOMEM, 12), (Self::ENFILE, 23), (Self::EMFILE, 24), (Self::ENOBUFS, 74), (Self::EINVAL, 22), (Self::ENOSYS, 109), (Self::ENOTSUP, 124), (Self::EOPNOTSUPP, 64), (Self::ETIMEDOUT, 78), (Self::EPIPE, 32), (Self::ECONNRESET, 73), (Self::ESHUTDOWN, 77)];
        #[cfg(target_os = "haiku")]
        return &[(Self::EPERM, -2147483633), (Self::EACCES, -2147483646), (Self::EINTR, -2147483638), (Self::EAGAIN, -2147483637), (Self::EWOULDBLOCK, -2147483637), (Self::ENOMEM, -2147483648), (Self::ENFILE, -2147454970), (Self::EMFILE, -2147459062), (Self::ENOBUFS, -2147454941), (Self::EINVAL, -2147483643), (Self::ENOSYS, -2147454967), (Self::ENOTSUP, -2147454920), (Self::EOPNOTSUPP, -2147454933), (Self::ETIMEDOUT, -2147483639), (Self::EPIPE, -2147459059), (Self::ECONNRESET, -2147454948), (Self::ESHUTDOWN, -2147454945)];
        #[cfg(any(target_os = "nto", target_os = "qnx"))]
        return &[(Self::EPERM, 1), (Self::EACCES, 13), (Self::EINTR, 4), (Self::EAGAIN, 11), (Self::EWOULDBLOCK, 11), (Self::ENOMEM, 12), (Self::ENFILE, 23), (Self::EMFILE, 24), (Self::ENOBUFS, 255), (Self::EINVAL, 22), (Self::ENOSYS, 89), (Self::ENOTSUP, 48), (Self::EOPNOTSUPP, 103), (Self::ETIMEDOUT, 260), (Self::EPIPE, 32), (Self::ECONNRESET, 254), (Self::ESHUTDOWN, 258)];
        #[cfg(target_os = "hurd")]
        return &[(Self::EPERM, 1073741825), (Self::EACCES, 1073741837), (Self::EINTR, 1073741828), (Self::EAGAIN, 1073741859), (Self::EWOULDBLOCK, 1073741859), (Self::ENOMEM, 1073741836), (Self::ENFILE, 1073741847), (Self::EMFILE, 1073741848), (Self::ENOBUFS, 1073741879), (Self::EINVAL, 1073741846), (Self::ENOSYS, 1073741902), (Self::ENOTSUP, 1073741942), (Self::EOPNOTSUPP, 1073741869), (Self::ETIMEDOUT, 1073741884), (Self::EPIPE, 1073741856), (Self::ECONNRESET, 1073741878), (Self::ESHUTDOWN, 1073741882)];
        #[cfg(target_os = "emscripten")]
        return &[(Self::EPERM, 63), (Self::EACCES, 2), (Self::EINTR, 27), (Self::EAGAIN, 6), (Self::EWOULDBLOCK, 6), (Self::ENOMEM, 48), (Self::ENFILE, 41), (Self::EMFILE, 33), (Self::ENOBUFS, 42), (Self::EINVAL, 28), (Self::ENOSYS, 52), (Self::ENOTSUP, 138), (Self::EOPNOTSUPP, 138), (Self::ETIMEDOUT, 73), (Self::EPIPE, 64), (Self::ECONNRESET, 15), (Self::ESHUTDOWN, 140)];
        #[cfg(target_os = "redox")]
        return &[(Self::EPERM, 1), (Self::EACCES, 13), (Self::EINTR, 4), (Self::EAGAIN, 11), (Self::EWOULDBLOCK, 41), (Self::ENOMEM, 12), (Self::ENFILE, 23), (Self::EMFILE, 24), (Self::ENOBUFS, 105), (Self::EINVAL, 22), (Self::ENOSYS, 38), (Self::ENOTSUP, 95), (Self::EOPNOTSUPP, 95), (Self::ETIMEDOUT, 110), (Self::EPIPE, 32), (Self::ECONNRESET, 104), (Self::ESHUTDOWN, 108)];
        #[cfg(target_os = "cygwin")]
        return &[(Self::EPERM, 1), (Self::EACCES, 13), (Self::EINTR, 4), (Self::EAGAIN, 11), (Self::EWOULDBLOCK, 11), (Self::ENOMEM, 12), (Self::ENFILE, 23), (Self::EMFILE, 24), (Self::ENOBUFS, 105), (Self::EINVAL, 22), (Self::ENOSYS, 88), (Self::ENOTSUP, 134), (Self::EOPNOTSUPP, 95), (Self::ETIMEDOUT, 116), (Self::EPIPE, 32), (Self::ECONNRESET, 104), (Self::ESHUTDOWN, 110)];
        #[cfg(target_env = "newlib")]
        return &[(Self::EPERM, 1), (Self::EACCES, 13), (Self::EINTR, 4), (Self::EAGAIN, 11), (Self::EWOULDBLOCK, 11), (Self::ENOMEM, 12), (Self::ENFILE, 23), (Self::EMFILE, 24), (Self::ENOBUFS, 105), (Self::EINVAL, 22), (Self::ENOSYS, 88), (Self::ENOTSUP, 134), (Self::EOPNOTSUPP, 95), (Self::ETIMEDOUT, 116), (Self::EPIPE, 32), (Self::ECONNRESET, 104)];
        #[cfg(target_os = "nuttx")]
        return &[(Self::EPERM, 1), (Self::EACCES, 13), (Self::EINTR, 4), (Self::EAGAIN, 11), (Self::EWOULDBLOCK, 11), (Self::ENOMEM, 12), (Self::ENFILE, 23), (Self::EMFILE, 24), (Self::ENOBUFS, 105), (Self::EINVAL, 22), (Self::ENOSYS, 38), (Self::ENOTSUP, 138), (Self::EOPNOTSUPP, 95), (Self::ETIMEDOUT, 110), (Self::EPIPE, 32), (Self::ECONNRESET, 104), (Self::ESHUTDOWN, 108)];
        #[cfg(target_os = "vxworks")]
        return &[(Self::EPERM, 1), (Self::EACCES, 13), (Self::EINTR, 4), (Self::EAGAIN, 11), (Self::EWOULDBLOCK, 70), (Self::ENOMEM, 12), (Self::ENFILE, 23), (Self::EMFILE, 24), (Self::ENOBUFS, 55), (Self::EINVAL, 22), (Self::ENOSYS, 71), (Self::ENOTSUP, 35), (Self::EOPNOTSUPP, 45), (Self::ETIMEDOUT, 60), (Self::EPIPE, 32), (Self::ECONNRESET, 54), (Self::ESHUTDOWN, 58)];
        #[cfg(target_os = "qurt")]
        return &[(Self::EPERM, 1), (Self::EACCES, 13), (Self::EINTR, 4), (Self::EAGAIN, 11), (Self::EWOULDBLOCK, 11), (Self::ENOMEM, 12), (Self::ENFILE, 23), (Self::EMFILE, 24), (Self::ENOBUFS, 105), (Self::EINVAL, 22), (Self::ENOSYS, 38), (Self::ENOTSUP, 95), (Self::EOPNOTSUPP, 95), (Self::ETIMEDOUT, 110), (Self::EPIPE, 32), (Self::ECONNRESET, 104), (Self::ESHUTDOWN, 108)];
        #[allow(unreachable_code)]
        &[]
    }

    pub fn number(&self) -> Option<i32> {
        Self::table().iter().find(|(errno, _)| errno == self).map(|(_, number)| *number)
    }

    pub fn from_number(number: i32) -> Option<Self> {
        Self::table().iter().find(|(_, value)| *value == number).map(|(errno, _)| *errno)
    }

    pub fn error(&self) -> ProviderError {
        match self {
            Self::EPERM | Self::EACCES => ProviderError::Permission,
            Self::EINTR => ProviderError::Interrupted,
            Self::EAGAIN | Self::EWOULDBLOCK => ProviderError::WouldBlock,
            Self::ENOMEM | Self::ENFILE | Self::EMFILE | Self::ENOBUFS => ProviderError::Exhausted,
            Self::EINVAL => ProviderError::Argument,
            Self::ENOSYS | Self::ENOTSUP | Self::EOPNOTSUPP => ProviderError::Unsupported,
            Self::ETIMEDOUT => ProviderError::Timeout,
            Self::EPIPE | Self::ECONNRESET | Self::ESHUTDOWN => ProviderError::Closed,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EPERM => "EPERM",
            Self::EACCES => "EACCES",
            Self::EINTR => "EINTR",
            Self::EAGAIN => "EAGAIN",
            Self::EWOULDBLOCK => "EWOULDBLOCK",
            Self::ENOMEM => "ENOMEM",
            Self::ENFILE => "ENFILE",
            Self::EMFILE => "EMFILE",
            Self::ENOBUFS => "ENOBUFS",
            Self::EINVAL => "EINVAL",
            Self::ENOSYS => "ENOSYS",
            Self::ENOTSUP => "ENOTSUP",
            Self::EOPNOTSUPP => "EOPNOTSUPP",
            Self::ETIMEDOUT => "ETIMEDOUT",
            Self::EPIPE => "EPIPE",
            Self::ECONNRESET => "ECONNRESET",
            Self::ESHUTDOWN => "ESHUTDOWN",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|errno| errno.as_str() == name)
    }
}
