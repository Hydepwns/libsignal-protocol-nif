# libsignal-protocol-nif

[![Hex.pm](https://img.shields.io/hexpm/v/libsignal_protocol_nif.svg)](https://hex.pm/packages/libsignal_protocol_nif)
[![Hex.pm](https://img.shields.io/hexpm/v/libsignal_protocol.svg)](https://hex.pm/packages/libsignal_protocol)
[![Hex.pm](https://img.shields.io/hexpm/v/libsignal_protocol_gleam.svg)](https://hex.pm/packages/libsignal_protocol_gleam)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](https://github.com/hydepwns/libsignal-protocol-nif)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Erlang NIF implementing Signal Protocol cryptographic primitives with libsodium.

> Jul-06 Status: ✅ CRYPTO IMPLEMENTATION COMPLETE
> **Implemented Cryptographic Functions:**
>
> - Curve25519 key pair generation (X25519 ECDH)
> - Ed25519 key pair generation and digital signatures
> - SHA-256 and SHA-512 hashing
> - HMAC-SHA256 authentication
> - AES-GCM encryption/decryption

## Quick Start

```bash
# Build the project
nix-shell --run "make build"

# Run crypto tests
nix-shell --run "rebar3 ct --suite=test/erl/unit/crypto/signal_crypto_SUITE.erl"
```

## Build

```bash
# Clean build
nix-shell --run "make clean && make build"

# Run all available tests
nix-shell --run "make test-unit"
```

## Cryptographic API

### Key Generation

```erlang
% Curve25519 key pairs (for ECDH key exchange)
{ok, {PublicKey, PrivateKey}} = signal_nif:generate_curve25519_keypair(),

% Ed25519 key pairs (for digital signatures)
{ok, {PublicKey, PrivateKey}} = signal_nif:generate_ed25519_keypair().
```

### Digital Signatures

```erlang
% Sign data with Ed25519
{ok, Signature} = signal_nif:sign_data(PrivateKey, Message),

% Verify signature
ok = signal_nif:verify_signature(PublicKey, Message, Signature).
```

### Hashing and Authentication

```erlang
% SHA-256 hashing
{ok, Hash} = signal_nif:sha256(Data),

% SHA-512 hashing
{ok, Hash} = signal_nif:sha512(Data),

% HMAC-SHA256 authentication
{ok, Hmac} = signal_nif:hmac_sha256(Key, Data).
```

### Encryption

```erlang
% AES-GCM encryption
{ok, Ciphertext, Tag} = signal_nif:aes_gcm_encrypt(Key, IV, Plaintext, AAD, TagLength),

% AES-GCM decryption
{ok, Plaintext} = signal_nif:aes_gcm_decrypt(Key, IV, Ciphertext, AAD, Tag, PlaintextLength).
```

## Implementation Details

- **Cryptography**: libsodium-based implementation
- **Key Sizes**: 32-byte keys for Curve25519 and Ed25519
- **Hash Sizes**: SHA-256 (32 bytes), SHA-512 (64 bytes)
- **Signature Size**: Ed25519 signatures are 64 bytes
- **Memory Management**: Secure memory clearing with `sodium_memzero()`
- **Error Handling**: Comprehensive error checking and reporting

## Language Wrappers

This project provides Signal Protocol implementations for multiple BEAM languages:

### Elixir Wrapper (`libsignal_protocol`)

The Elixir wrapper provides idiomatic Elixir APIs for Signal Protocol operations.

```elixir
# Add to mix.exs
def deps do
  [
    {:libsignal_protocol, "~> 0.1.0"}
  ]
end
```

**Available Modules:**

- `SignalProtocol` - Core cryptographic operations
- `Session` - Session management and key exchange
- `PreKeyBundle` - Pre-key bundle handling
- `LibsignalProtocol` - Main interface module

### Gleam Wrapper (`libsignal_protocol_gleam`)

The Gleam wrapper provides type-safe Signal Protocol operations with Gleam's type system.

```toml
# Add to gleam.toml
[dependencies]
libsignal_protocol_gleam = "~> 0.1.0"
```

**Available Modules:**

- `signal_protocol` - Core cryptographic operations
- `session` - Session management and key exchange
- `pre_key_bundle` - Pre-key bundle handling
- `utils` - Utility functions and type conversions

### Cross-Language Compatibility

All wrappers use the same underlying NIF implementation, ensuring:

- Consistent cryptographic behavior across languages
- Shared memory efficiency through NIFs
- Identical performance characteristics
- Cross-language session compatibility
