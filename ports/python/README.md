# umineko.py
Python bindings for Umineko

## Requirements

- Linux / Darwin / Windows (32-bit or 64-bit x86/AArch/RISC-V)
- Python 3.8+

## Installation

```bash
uv add umineko
```

The library is loaded dynamically. The library to load is tried in the following order: the `UMINEKO_LIBRARY` environment variable, the shared object embedded at build time, and the system loader.

## Links
- [crates.io](https://crates.io/crates/umineko/) - Rust crate
- [pypi.org](https://pypi.org/project/umineko/) - Python package
- [docs.rs](https://docs.rs/umineko/) - Documentation (for the Rust crate)
- [deepwiki.com](https://deepwiki.com/nercone-dev/umineko/) - Documentation; Automatically generated.
