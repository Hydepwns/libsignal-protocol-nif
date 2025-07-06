# Architecture

## Overview

Erlang NIF implementing Signal Protocol cryptographic primitives with libsodium backend.

## Components

- **Primary NIF**: `c_src/signal_nif.c` - Core crypto implementation with libsodium
- **Erlang Module**: `erl_src/signal_nif.erl` - Erlang interface with robust path loading
- **Test Suite**: `test/erl/unit/crypto/signal_crypto_SUITE.erl` - Comprehensive crypto validation

## Implemented Cryptographic Primitives

- **Key Generation**: Curve25519 (X25519) and Ed25519 key pairs
- **Digital Signatures**: Ed25519 signing and verification
- **Hashing**: SHA-256 and SHA-512
- **Authentication**: HMAC-SHA256
- **Encryption**: AES-GCM with authentication

## Data Flow

```c
Erlang API → NIF Interface → libsodium → Cryptographic Operations
```

## NIF Loading Strategy

Multiple path fallback system for robust loading across development and test environments:

- Project root paths
- Rebar3 test environment paths  
- Application-relative paths
- Filesystem traversal for priv directory discovery

## Build System

- **CMake**: C compilation with proper libsodium linking
- **Rebar3**: Erlang compilation and test execution
- **Make**: Unified build orchestration with NIF distribution

## Memory Management

- Secure memory clearing with `sodium_memzero()` for sensitive data
- Proper EVP_PKEY lifecycle management
- Error-safe resource cleanup

## Known Limitations

- Linux x86_64 primary target (macOS supported)
- NixOS/Nix environment required for reproducible builds
- Test infrastructure has some rebar3 profile compilation issues
