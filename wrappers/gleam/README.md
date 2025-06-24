# libsignal-protocol-gleam

Gleam wrapper for Signal Protocol NIF with FFI integration to Elixir.

## Installation

```toml
[dependencies]
libsignal_protocol_gleam = "~> 0.1.0"
```

## Usage

```gleam
import signal_protocol

pub fn main() {
  // Generate keys
  case signal_protocol.generate_identity_key_pair() {
    Ok(identity_pair) -> {
      // Create session
      case signal_protocol.create_session(identity_pair.public_key, remote_key) {
        Ok(session) -> {
          // Encrypt/decrypt
          case signal_protocol.encrypt_message(session, "Hello") {
            Ok(encrypted) -> {
              signal_protocol.decrypt_message(session, encrypted)
            }
            Error(e) -> Error(e)
          }
        }
        Error(e) -> Error(e)
      }
    }
    Error(e) -> Error(e)
  }
}
```

## API

### signal_protocol

- `generate_identity_key_pair()` → `Result(IdentityKeyPair, String)`
- `generate_pre_key(id: Int)` → `Result(PreKey, String)`
- `generate_signed_pre_key(identity_key: String, id: Int)` → `Result(SignedPreKey, String)`
- `create_session(local: String, remote: String)` → `Result(Session, String)`
- `encrypt_message(session: Session, message: String)` → `Result(String, String)`
- `decrypt_message(session: Session, ciphertext: String)` → `Result(String, String)`

### signal_protocol/session

- `create(local: String, remote: String)` → `Result(Session, String)`
- `send_message(session: Session, message: String)` → `Result(String, String)`
- `receive_message(session: Session, ciphertext: String)` → `Result(String, String)`

### signal_protocol/pre_key_bundle

- `create(reg_id: Int, identity: String, pre_key: PreKey, signed_pre_key: SignedPreKey, base_key: String)` → `Result(PreKeyBundle, String)`
- `parse(bundle: String)` → `Result(PreKeyBundle, String)`
- `verify_signature(bundle: PreKeyBundle)` → `Result(Nil, String)`

### signal_protocol/utils

- `generate_user_keys()` → `Result(#(IdentityKeyPair, PreKey, SignedPreKey), String)`
- `establish_session(...)` → `Result(#(Session, Session), String)`
- `exchange_messages(local: Session, remote: Session, message: String)` → `Result(#(String, Session, Session), String)`

## Build

```bash
cd wrappers/gleam
gleam build
```

## Test

```bash
cd wrappers/gleam
gleam test
```

## Requirements

- Gleam 0.37+
- Erlang/OTP 25+
- Elixir SignalProtocol implementation

## License

MIT
