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

### Test Groups

The test suites are organized into two groups to handle expensive cryptographic operations:

- **Fast tests**: Basic functionality, error handling, and simple operations
- **Expensive tests**: Concurrent operations, large data processing, and stress tests

### Running Tests

**Run only fast tests (recommended for development):**

```bash
rebar3 as test ct --group fast --cover
```

**Run only expensive tests:**

```bash
rebar3 as test ct --group expensive
```

**Run all tests (may take a long time):**

```bash
rebar3 as test ct --cover
```

**Run specific test suites:**

```bash
# Fast tests only
rebar3 as test ct --suite=test/erl/protocol_SUITE --group fast --cover

# All tests in a suite
rebar3 as test ct --suite=test/erl/protocol_SUITE --cover
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
