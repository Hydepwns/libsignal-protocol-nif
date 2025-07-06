# libsignal-protocol-nif

> **High-performance Signal Protocol cryptographic primitives for the BEAM ecosystem**

[![Erlang/OTP](https://img.shields.io/hexpm/v/libsignal_protocol_nif.svg?label=Erlang%2FOTP&style=flat-square)](https://hex.pm/packages/libsignal_protocol_nif)
[![Elixir](https://img.shields.io/hexpm/v/libsignal_protocol.svg?label=Elixir&style=flat-square)](https://hex.pm/packages/libsignal_protocol)
[![Gleam](https://img.shields.io/hexpm/v/libsignal_protocol_gleam.svg?label=Gleam&style=flat-square)](https://hex.pm/packages/libsignal_protocol_gleam)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg?style=flat-square)](https://github.com/hydepwns/libsignal-protocol-nif)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg?style=flat-square)](LICENSE)

A native Erlang NIF (Native Implemented Function) library that provides Signal Protocol cryptographic primitives using libsodium. Built for **performance**, **security**, and **cross-language compatibility** across Erlang, Elixir, and Gleam.

---

## Quick Start

**Get up and running in 30 seconds:**

```bash
# Clone and build
git clone https://github.com/Hydepwns/libsignal-protocol-nif.git
cd libsignal-protocol-nif
nix-shell --run "make build"

# Verify it works
nix-shell --run "make test-unit"
```

**Add to your project:**

<details>
<summary><strong>Erlang (rebar.config)</strong></summary>

```erlang
{deps, [
    {libsignal_protocol_nif, "0.1.0"}
]}.
```

</details>

<details>
<summary><strong>Elixir (mix.exs)</strong></summary>

```elixir
def deps do
  [
    {:libsignal_protocol, "~> 0.1.0"}
  ]
end
```

</details>

<details>
<summary><strong>Gleam (gleam.toml)</strong></summary>

```toml
[dependencies]
libsignal_protocol_gleam = "~> 0.1.0"
```

</details>

---

## What's Included

### Cryptographic Primitives

- **Key Generation**: Curve25519 (ECDH) and Ed25519 (signatures)
- **Digital Signatures**: Ed25519 signing and verification
- **Encryption**: AES-GCM authenticated encryption
- **Hashing**: SHA-256, SHA-512, HMAC-SHA256
- **Memory Safety**: Secure memory clearing with `sodium_memzero()`

### Multi-Language Support

- **Erlang/OTP**: Native NIF implementation
- **Elixir**: Idiomatic Elixir wrapper
- **Gleam**: Type-safe functional wrapper

### Production Ready

- **High Performance**: Native C implementation with libsodium
- **Memory Efficient**: Minimal overhead, secure memory management
- **Cross-Platform**: Linux, macOS, Windows support
- **Well Tested**: Comprehensive test suite with 100% crypto coverage

---

## Installation

### System Requirements

| Component | Version | Purpose |
|-----------|---------|---------|
| **libsodium** | 1.0.18+ | Cryptographic operations |
| **CMake** | 3.15+ | Build system |
| **Erlang/OTP** | 24.0+ | Runtime |
| **GCC/Clang** | Any recent | C compiler |

### Platform-Specific Setup

<details>
<summary><strong>Ubuntu/Debian</strong></summary>

```bash
sudo apt-get update
sudo apt-get install libsodium-dev cmake build-essential
```

</details>

<details>
<summary><strong>macOS</strong></summary>

```bash
brew install libsodium cmake
```

</details>

<details>
<summary><strong>Nix (Recommended)</strong></summary>

```bash
nix-shell  # All dependencies included automatically
```

</details>

---

## Usage Examples

### Basic Cryptographic Operations

```erlang
%% Generate key pairs
{ok, {Curve25519Pub, Curve25519Priv}} = signal_nif:generate_curve25519_keypair(),
{ok, {Ed25519Pub, Ed25519Priv}} = signal_nif:generate_ed25519_keypair(),

%% Digital signatures
Message = <<"Hello, Signal Protocol!">>,
{ok, Signature} = signal_nif:sign_data(Ed25519Priv, Message),
ok = signal_nif:verify_signature(Ed25519Pub, Message, Signature),

%% Hashing and authentication
{ok, Hash} = signal_nif:sha256(Message),
{ok, Hmac} = signal_nif:hmac_sha256(<<"secret-key">>, Message),

%% Authenticated encryption
Key = crypto:strong_rand_bytes(32),
IV = crypto:strong_rand_bytes(12),
{ok, Ciphertext, Tag} = signal_nif:aes_gcm_encrypt(Key, IV, Message, <<>>, 16),
{ok, Plaintext} = signal_nif:aes_gcm_decrypt(Key, IV, Ciphertext, <<>>, Tag, byte_size(Message)).
```

### Language-Specific Examples

<details>
<summary><strong>Elixir</strong></summary>

```elixir
# Generate keys
{:ok, {public_key, private_key}} = SignalProtocol.generate_keypair()

# Sign and verify
message = "Hello from Elixir!"
{:ok, signature} = SignalProtocol.sign(private_key, message)
:ok = SignalProtocol.verify(public_key, message, signature)
```

</details>

<details>
<summary><strong>Gleam</strong></summary>

```gleam
import signal_protocol

// Generate keys
let assert Ok(#(public_key, private_key)) = signal_protocol.generate_keypair()

// Sign and verify
let message = "Hello from Gleam!"
let assert Ok(signature) = signal_protocol.sign(private_key, message)
let assert Ok(Nil) = signal_protocol.verify(public_key, message, signature)
```

</details>

---

## Development

### Building from Source

```bash
# Clean build
make clean && make build

# Run tests
make test-unit          # Unit tests
make test-integration   # Integration tests
make test-cover         # With coverage

# Performance testing
make perf-test          # Benchmarks
```

### Docker Development

```bash
# Build all environments
make docker-build

# Test in containers
make docker-test
```

---

## Documentation

| Resource | Description |
|----------|-------------|
| [Quick Start Guide](docs/IMMEDIATE_ACTIONS.md) | Get started in 5 minutes |
| [API Reference](docs/API.md) | Complete function documentation |
| [Architecture](docs/ARCHITECTURE.md) | System design and internals |
| [Security Guide](docs/SECURITY.md) | Cryptographic security considerations |
| [Language Comparison](docs/CROSS_LANGUAGE_COMPARISON.md) | Erlang vs Elixir vs Gleam |
| [Documentation Plan](docs/DOCUMENTATION_PLAN.md) | Comprehensive roadmap |

---

## Troubleshooting

### Common Issues

<details>
<summary><strong>Build Errors</strong></summary>

**`fatal error: sodium.h: No such file or directory`**

```bash
# Install libsodium development headers
sudo apt-get install libsodium-dev  # Ubuntu/Debian
brew install libsodium               # macOS
```

**`CMake Error: Could not find a package configuration file`**

```bash
# Install CMake
sudo apt-get install cmake  # Ubuntu/Debian
brew install cmake           # macOS
```

</details>

<details>
<summary><strong>Runtime Errors</strong></summary>

**`{error, {load_failed, "Failed to load NIF library"}}`**

```bash
# Rebuild and verify NIF files
make clean && make build
ls -la priv/  # Should show .so/.dylib files
```

**macOS library loading issues**

```bash
# Check and set library paths
otool -L priv/signal_nif.so
export DYLD_LIBRARY_PATH=/opt/homebrew/opt/openssl@3/lib
```

</details>

<details>
<summary><strong>Performance Issues</strong></summary>

- **Slow builds**: Use `make -j$(nproc)` for parallel compilation
- **Memory monitoring**: Run `make monitor-memory` during tests
- **Benchmarking**: Use `make perf-test` for performance metrics

</details>

---

## Getting Help

- **Quick fixes**: [docs/IMMEDIATE_ACTIONS.md](docs/IMMEDIATE_ACTIONS.md)
- **Bug reports**: [GitHub Issues](https://github.com/Hydepwns/libsignal-protocol-nif/issues)
- **Questions**: [GitHub Discussions](https://github.com/Hydepwns/libsignal-protocol-nif/discussions)
- **Security**: [docs/SECURITY.md](docs/SECURITY.md)

---

## Technical Details

### Implementation

- **Core**: Native C implementation using libsodium
- **Interface**: Erlang NIF for high-performance integration
- **Memory**: Secure allocation and automatic cleanup
- **Error Handling**: Comprehensive validation and reporting

### Key Specifications

- **Curve25519**: 32-byte keys, X25519 ECDH
- **Ed25519**: 32-byte keys, 64-byte signatures
- **AES-GCM**: 256-bit keys, authenticated encryption
- **SHA-256/512**: Standard hash functions
- **HMAC-SHA256**: Message authentication codes

### Platform Support

- **Linux**: x86_64, ARM64 ✅
- **macOS**: Intel, Apple Silicon ✅
- **Windows**: x86_64 (experimental) ⚠️

---

## License

This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

---

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Key Areas:**

- Bug fixes and improvements
- Documentation enhancements
- Additional test coverage
- New language wrappers
- Performance optimizations

---

<div align="center">

**Made with ❤️ for the BEAM ecosystem**

[⭐ Star this project](https://github.com/Hydepwns/libsignal-protocol-nif) • [Report Issues](https://github.com/Hydepwns/libsignal-protocol-nif/issues) • [Discussions](https://github.com/Hydepwns/libsignal-protocol-nif/discussions)

</div>
