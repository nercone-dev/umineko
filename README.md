# umineko
Pure-Rust implementations of everything

## Overview

Pure-Rust implementations of everything, including protocols such as HTTP and TLS, and algorithms such as SHA256 and MD5.

C FFI and Python bindings are also provided.

## Requirements

- Rust 1.85+ (2024 edition)
- C/C++ Toolchain (for C FFI, LLVM/clang recommended)

### Platform

Umineko is completely platform-independent and works in no_std environments.
However, if platform-specific implementations or supported external libraries (referred to as "providers") are available, they will be used with priority. (This is the default behavior and can be changed later.)
The following list shows the providers natively supported by Umineko.

```
Linux   5.14-7.2          x86/x86_64/AArch32/AArch64/RISCV32/RISCV64
Darwin  20.0-27.0         x86/x86_64/AArch32/AArch64                 (macOS 11+ / iOS 14+ / iPadOS 14+ / visionOS 1+ / watchOS 7+ / tvOS 14+ / bridgeOS 5+)
Android 12-17             x86/x86_64/AArch32/AArch64/RISCV32/RISCV64
Windows 7/8/8.1/10/11     x86/x86_64/AArch64
FreeBSD                   x86/x86_64/AArch32/AArch64
OpenBSD                   x86/x86_64/AArch32/AArch64
NetBSD                    x86/x86_64/AArch32/AArch64
WASI    preview1/preview2 WASM
```

## Installation

```bash
cargo add umineko
```

```bash
uv add umineko
```

## Links
- [crates.io](https://crates.io/crates/umineko/) - Rust crate
- [pypi.org](https://pypi.org/project/umineko/) - Python package
- [docs.rs](https://docs.rs/umineko/) - Documentation (for the Rust crate)
- [deepwiki.com](https://deepwiki.com/nercone-dev/umineko/) - Documentation; Automatically generated.
