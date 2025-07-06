# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Improved README badges with clear language labels
- Comprehensive security documentation (SECURITY.md)
- Quick start guide (IMMEDIATE_ACTIONS.md)
- This changelog file

### Changed

- Cleaned up project root (removed crash dump files)
- Improved documentation structure and references

### Fixed

- Trimmed trailing whitespace in VERSION file

## [0.1.0] - 2024-07-06

### Added

- Complete cryptographic implementation using libsodium
- Curve25519 key pair generation (X25519 ECDH)
- Ed25519 key pair generation and digital signatures
- SHA-256 and SHA-512 hashing functions
- HMAC-SHA256 authentication
- AES-GCM encryption/decryption with authenticated encryption
- Comprehensive test suite for all cryptographic operations
- Multi-language support with Erlang, Elixir, and Gleam wrappers
- Cross-platform build system (Linux, macOS, Windows)
- Nix-based development environment
- Docker support for containerized builds
- Comprehensive documentation including:
  - API reference documentation
  - Architecture and implementation details
  - Cross-language comparison guide
  - Contributing guidelines
- Memory-safe implementation with proper cleanup
- Error handling and input validation
- Performance optimizations

### Security

- Secure memory management with `sodium_memzero()`
- Constant-time cryptographic operations via libsodium
- Proper key validation and error handling
- No sensitive data logging or exposure

### Technical Details

- **Erlang NIF**: High-performance native implementation
- **libsodium**: Industry-standard cryptographic library
- **CMake**: Cross-platform build system
- **rebar3**: Erlang build tool and package manager
- **Hex.pm**: Package distribution for all BEAM languages

## [0.0.1] - Initial Development

### Added

- Initial project structure
- Basic NIF scaffolding
- Build system setup
- Development environment configuration

---

## Release Notes

### Version 0.1.0 - "Crypto Complete"

This is the first stable release of libsignal-protocol-nif, featuring a complete implementation of Signal Protocol cryptographic primitives. The library provides high-performance, memory-safe cryptographic operations for Erlang, Elixir, and Gleam applications.

**Key Features:**

- ✅ All major cryptographic primitives implemented
- ✅ Comprehensive test coverage
- ✅ Multi-language wrapper support
- ✅ Production-ready security measures
- ✅ Cross-platform compatibility

**Performance:**

- Optimized for high-throughput applications
- Memory-efficient with proper cleanup
- Minimal overhead NIFs

**Security:**

- Based on audited libsodium library
- Constant-time operations
- Secure memory management
- Comprehensive input validation

### Migration Guide

This is the initial release, so no migration is needed. For future releases, migration guides will be provided here.

### Known Issues

- None currently identified

### Supported Platforms

- **Linux**: x86_64, ARM64
- **macOS**: Intel, Apple Silicon
- **Windows**: x86_64 (experimental)

### Dependencies

- **Erlang/OTP**: 24.0 or later
- **libsodium**: 1.0.18 or later
- **CMake**: 3.15 or later
- **rebar3**: 3.20 or later

### Contributors

- [@hydepwns](https://github.com/hydepwns) - Initial implementation and maintenance

---

## Future Roadmap

### Planned Features

- [ ] Additional Signal Protocol features (if needed)
- [ ] Performance benchmarking suite
- [ ] Windows native support improvements
- [ ] Additional language wrappers (Rust, Go, etc.)
- [ ] Hardware security module (HSM) support
- [ ] Formal security audit

### Long-term Goals

- Become the reference implementation for Signal Protocol cryptography in BEAM languages
- Maintain compatibility with Signal Protocol specification updates
- Provide the highest performance cryptographic operations for Erlang ecosystem
