# Architecture

## Overview

Erlang NIF implementing Signal Protocol cryptography with libsodium backend.

## Components

- **NIF Layer**: `c_src/libsignal_protocol_nif.c` - C implementation with libsodium
- **Erlang Module**: `erl_src/libsignal_protocol_nif.erl` - Erlang interface
- **Verification**: `verify_foundation.sh` - Crypto validation script

## Cryptographic Primitives

- **Key Generation**: Curve25519 (32-byte keys)
- **Key Agreement**: ECDH with Curve25519
- **Encryption**: ChaCha20-Poly1305 AEAD
- **Signatures**: HMAC-SHA256 for pre-keys
- **Session State**: 64-byte session management

## Data Flow

```
Erlang → NIF → libsodium → Cryptographic Operations
```

## Build Dependencies

- NixOS/Nix environment
- libsodium library
- C compiler toolchain

## Known Limitations

- ARM64 architecture not supported (segfault issue)
- AMD64 architecture required
- NixOS/Nix environment required for builds
