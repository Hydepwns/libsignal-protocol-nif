# libsignal-protocol-nif

Cross-platform BEAM wrappers (Erlang/Elixir/Gleam) for the Signal Protocol library, implemented with OpenSSL cryptographic primitives.

## Features

- End-to-end encryption using Signal Protocol
- Session management and pre-key bundle handling
- Message encryption/decryption with perfect forward secrecy
- Cross-platform support (Linux, macOS, Windows)
- OpenSSL-based cryptographic primitives

## Quick Start

```bash
make build      # Build everything
make test       # Run tests
```

## Installation & Usage

<details>
<summary><strong>Erlang</strong></summary>

### Installation

```erlang
{deps, [{libsignal_protocol_nif, {git, "https://github.com/Hydepwns/libsignal-protocol-nif.git"}}]}.
```

### Usage

```erlang
ok = libsignal_protocol_nif:init(),
{ok, {Pub, Priv}} = libsignal_protocol_nif:generate_identity_key_pair(),
{ok, Session} = libsignal_protocol_nif:create_session(Pub, RemotePub),
{ok, Encrypted} = libsignal_protocol_nif:encrypt_message(Session, "Hello!"),
{ok, Decrypted} = libsignal_protocol_nif:decrypt_message(Session, Encrypted).
```

</details>

<details>
<summary><strong>Elixir</strong></summary>

### Installation

```elixir
{:libsignal_protocol_nif, "~> 0.1.0"}
```

### Usage

```elixir
{:ok, pid} = SignalProtocol.start_link()
{:ok, {Pub, Priv}} = SignalProtocol.generate_identity_key_pair()
{:ok, session} = SignalProtocol.create_session(Pub, RemotePub)
{:ok, encrypted} = SignalProtocol.encrypt_message(session, "Hello!")
{:ok, decrypted} = SignalProtocol.decrypt_message(session, encrypted)
```

</details>

<details>
<summary><strong>Gleam</strong></summary>

### Installation

See `wrappers/gleam/README.md`

### Usage

```gleam
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

</details>

## Building

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

### Testing

```bash
make test       # Run tests
```
