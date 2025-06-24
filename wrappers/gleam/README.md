# libsignal-protocol-gleam

Gleam wrapper for the Signal Protocol NIF library.

## Installation

Add to your `gleam.toml`:

```toml
[dependencies]
libsignal_protocol_gleam = "~> 0.1.0"
```

## Usage

```gleam
import libsignal_protocol_gleam

pub fn main() {
  // Initialize the library
  case libsignal_protocol_gleam.init() {
    Ok(_) -> {
      // Generate identity keys
      case libsignal_protocol_gleam.generate_identity_key_pair() {
        Ok(identity_pair) -> {
          // Create a session
          case libsignal_protocol_gleam.create_session(
            identity_pair.public_key,
            remote_identity_key
          ) {
            Ok(session) -> {
              // Encrypt a message
              case libsignal_protocol_gleam.encrypt_message(session, "Hello!") {
                Ok(encrypted) -> {
                  // Decrypt the message
                  case libsignal_protocol_gleam.decrypt_message(session, encrypted) {
                    Ok(decrypted) -> {
                      // Use decrypted message
                      Ok(decrypted)
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
        Error(e) -> Error(e)
      }
    }
    Error(e) -> Error(e)
  }
}
```

## API Reference

### Types

- `Session` - Represents a Signal Protocol session
- `PreKeyBundle` - Represents a pre-key bundle for session establishment
- `IdentityKeyPair` - Represents an identity key pair
- `PreKey` - Represents a pre-key
- `SignedPreKey` - Represents a signed pre-key

### Functions

- `init()` - Initialize the Signal Protocol library
- `generate_identity_key_pair()` - Generate a new identity key pair
- `generate_pre_key(key_id)` - Generate a new pre-key
- `generate_signed_pre_key(identity_key, key_id)` - Generate a signed pre-key
- `create_session(local_identity_key, remote_identity_key)` - Create a new session
- `process_pre_key_bundle(session, bundle)` - Process a pre-key bundle
- `encrypt_message(session, message)` - Encrypt a message
- `decrypt_message(session, ciphertext)` - Decrypt a message

## Building

```bash
gleam build
```

## Testing

```bash
gleam test
```

## License

MIT License - see the main project LICENSE file for details.
