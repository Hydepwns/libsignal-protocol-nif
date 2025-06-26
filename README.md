# libsignal-protocol-nif

Cross-platform BEAM wrappers (Erlang/Elixir/Gleam) for the Signal Protocol library, implemented with OpenSSL cryptographic primitives.

## Architecture

- **NIF Layer**: C implementation using OpenSSL for cryptographic operations
- **Erlang Interface**: GenServer-based API for session management
- **Multi-language Support**: Wrappers for Elixir and Gleam

## Features

- End-to-end encryption using Signal Protocol
- Session management and pre-key bundle handling
- Message encryption/decryption with perfect forward secrecy
- Cross-platform support (Linux, macOS, Windows)
- OpenSSL-based cryptographic primitives

## Current Status

### Test Results (Latest Run)

- **Overall Success Rate**: 75% (6/8 tests passing)
- **Passing Tests**: 6 out of 8
- **Failing Tests**: 2 out of 8

### ✅ Working Functionality

- Basic crypto initialization
- Curve25519 key pair generation
- SHA-256 and SHA-512 hashing
- HMAC-SHA256
- AES-GCM encryption/decryption

### ❌ Known Issues

- **Ed25519 Key Generation**: Returns 64-byte public keys instead of expected 32-byte keys
- **Ed25519 Signing/Verification**: Fails due to incorrect key format
- **Missing C Source Files**: `c_src/CMakeLists.txt` referenced in Makefile but not present
- **NIF Loading Issues**: Some test modules fail to load due to missing NIF libraries

### 🔧 Development Status

- Core cryptographic operations are functional
- Signal Protocol primitives working correctly
- Ed25519 digital signatures need implementation fixes
- Build system requires C source files to be added

## Quick Start

```bash
# Git + Makefile
git clone https://github.com/Hydepwns/libsignal-protocol-nif.git
cd libsignal-protocol-nif
make build      # Build everything
make ci-build   # Build for CI
make test       # Run tests
make clean      # Clean build artifacts (optional)
make clean-all  # Clean build artifacts and dependencies (optional)
```

## Installation

### Erlang

```erlang
% rebar.config
{deps, [{libsignal_protocol_nif, {git, "https://github.com/Hydepwns/libsignal-protocol-nif.git"}}]}.
```

### Elixir

```elixir
# mix.exs
mix deps.add libsignal_protocol_nif --git "https://github.com/Hydepwns/libsignal-protocol-nif.git"
mix deps.get
```

```elixir
# mix.exs
{:libsignal_protocol_nif, git: "https://github.com/Hydepwns/libsignal-protocol-nif.git"}
```

### Gleam

```toml
# gleam.toml
[dependencies]
libsignal_protocol_gleam = "~> 0.1.0"
```

## Building & Testing

### Unified Build (Recommended)

```bash
make build      # Build everything
make test       # Run tests
```

### Platform-Specific Builds

```bash
make build-erlang  # Build Erlang NIF
make build-elixir  # Build Elixir wrapper
make build-gleam   # Build Gleam wrapper
```

## Usage (Erlang/Elixir/Gleam)

```erlang
% example.erl
ok = libsignal_protocol_nif:init(),
{ok, {Pub, Priv}} = libsignal_protocol_nif:generate_identity_key_pair(),
{ok, Session} = libsignal_protocol_nif:create_session(Pub, RemotePub),
{ok, Encrypted} = libsignal_protocol_nif:encrypt_message(Session, "Hello!"),
{ok, Decrypted} = libsignal_protocol_nif:decrypt_message(Session, Encrypted).
```

```elixir
# example.exs
{:ok, pid} = SignalProtocol.start_link()
{:ok, {Pub, Priv}} = SignalProtocol.generate_identity_key_pair()
{:ok, session} = SignalProtocol.create_session(Pub, RemotePub)
{:ok, encrypted} = SignalProtocol.encrypt_message(session, "Hello!")
{:ok, decrypted} = SignalProtocol.decrypt_message(session, encrypted)
```

```gleam
// example.gleam
case libsignal_protocol_gleam.init() {
  Ok(_) -> case libsignal_protocol_gleam.generate_identity_key_pair() {
    Ok(keys) -> case libsignal_protocol_gleam.create_session(Pub, RemotePub) {
      Ok(session) -> case libsignal_protocol_gleam.encrypt_message(session, "Hello!") {
        Ok(encrypted) -> libsignal_protocol_gleam.decrypt_message(session, encrypted)
        Error(e) -> Error(e)
      }
      Error(e) -> Error(e)
    }
    Error(e) -> Error(e)
  }
  Error(e) -> Error(e)
}
```

## Testing (Erlang)

### Test Organization

The test suite is organized into three main categories:

- **Unit Tests** (`test/erl/unit/`): Individual module tests organized by functionality

  - `crypto/`: Cryptographic operations and key management
  - `protocol/`: Signal Protocol implementation
  - `session/`: Session management and state handling
  - `nif/`: NIF-specific functionality and caching

- **Integration Tests** (`test/erl/integration/`): End-to-end workflow tests

  - Complete Signal Protocol workflows
  - Performance and stress tests

- **Smoke Tests** (`test/erl/smoke/`): Quick validation tests
  - Basic functionality verification
  - Module loading and initialization

### Running Tests

**Current Test Status:**

```bash
# Run all tests (6/8 passing, 2 failing)
make test

# Run individual passing tests
rebar3 ct --suite=test/erl/unit/crypto/signal_crypto_SUITE --case=test_basic_crypto
rebar3 ct --suite=test/erl/unit/crypto/signal_crypto_SUITE --case=test_curve25519_keypair
rebar3 ct --suite=test/erl/unit/crypto/signal_crypto_SUITE --case=test_sha256
rebar3 ct --suite=test/erl/unit/crypto/signal_crypto_SUITE --case=test_aes_gcm_encryption
```

**Run all tests:**

```bash
make test
```

**Run specific test categories:**

```bash
make test-unit          # Unit tests only
make test-integration   # Integration tests only
make test-smoke         # Smoke tests only
```

**Run tests with coverage:**

```bash
make test-cover         # All tests with coverage
make test-unit-cover    # Unit tests with coverage
make test-integration-cover  # Integration tests with coverage
```

**Run specific test suites using rebar3:**

```bash
# Unit tests
rebar3 as unit ct --suite=test/erl/unit/crypto/signal_crypto_SUITE
rebar3 as unit ct --suite=test/erl/unit/protocol/protocol_SUITE
rebar3 as unit ct --suite=test/erl/unit/session/signal_session_SUITE

# Integration tests
rebar3 as integration ct --suite=test/erl/integration/integration_SUITE

# Smoke tests
rebar3 as smoke ct --suite=test/erl/smoke/simple_test_SUITE
```

**Run tests by groups (fast/expensive):**

```bash
# Fast tests only
rebar3 as test ct --group fast --cover

# Expensive tests only
rebar3 as test ct --group expensive
```

### Test Coverage

**Individual test suite coverage:**

```bash
rebar3 cover
```

The coverage report will be available in `_build/test/cover/index.html`.

**Combined coverage from all test suites:**

```bash
./scripts/aggregate_coverage.sh
```

This script runs all test suites sequentially and accumulates coverage data, providing a comprehensive coverage report across all modules.

## Advanced Usage (Erlang) (Optional)

```erlang
% Initialize the NIF
ok = nif:init().

% Generate identity key pair
{ok, {PublicKey, PrivateKey}} = nif:generate_identity_key_pair().

% Generate pre-key
{ok, {KeyId, PreKey}} = nif:generate_pre_key(12345).

% Generate signed pre-key
{ok, {KeyId, SignedPreKey, Signature}} = nif:generate_signed_pre_key(IdentityKey, 67890).

% Create session
{ok, Session} = nif:create_session(IdentityKey).

% Process pre-key bundle
{ok, UpdatedSession} = nif:process_pre_key_bundle(Session, Bundle).

% Encrypt message
{ok, EncryptedMessage} = nif:encrypt_message(Session, Message).

% Decrypt message
{ok, DecryptedMessage} = nif:decrypt_message(Session, EncryptedMessage).
```

## License

[MIT](LICENSE)
