# libsignal_protocol_gleam

[![Hex.pm](https://img.shields.io/hexpm/v/libsignal_protocol_gleam.svg)](https://hex.pm/packages/libsignal_protocol_gleam)
[![Hex.pm](https://img.shields.io/hexpm/dt/libsignal_protocol_gleam.svg)](https://hex.pm/packages/libsignal_protocol_gleam)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Gleam wrapper for Signal Protocol cryptographic primitives with libsodium.

This package provides type-safe Gleam APIs for Signal Protocol operations, including key generation, digital signatures, encryption, and session management.

## Installation

Add `libsignal_protocol_gleam` to your list of dependencies in `gleam.toml`:

```toml
[dependencies]
libsignal_protocol_gleam = "~> 0.1.1"
```

## Quick Start

```gleam
import libsignal_protocol_gleam/signal_protocol
import libsignal_protocol_gleam/session
import gleam/result

// Initialize the library
let Ok(_) = signal_protocol.init()

// Generate identity key pair
let Ok(#(public_key, private_key)) = signal_protocol.generate_identity_key_pair()

// Generate pre-key
let Ok(#(key_id, pre_key)) = signal_protocol.generate_pre_key(1)

// Create session
let Ok(session) = signal_protocol.create_session(public_key)

// Encrypt message
let Ok(encrypted) = signal_protocol.encrypt_message(session, "Hello, Signal!")

// Decrypt message
let Ok(decrypted) = signal_protocol.decrypt_message(session, encrypted)
```

## Available Modules

### `signal_protocol`

Core cryptographic operations and key management.

```gleam
import libsignal_protocol_gleam/signal_protocol

// Key generation
let Ok(#(public, private)) = signal_protocol.generate_identity_key_pair()
let Ok(#(key_id, pre_key)) = signal_protocol.generate_pre_key(1)
let Ok(#(key_id, signed_pre_key)) = signal_protocol.generate_signed_pre_key(private, 2)

// Session management
let Ok(session) = signal_protocol.create_session(remote_public_key)
let Ok(session) = signal_protocol.create_session(local_private_key, remote_public_key)

// Message encryption/decryption
let Ok(encrypted) = signal_protocol.encrypt_message(session, message)
let Ok(decrypted) = signal_protocol.decrypt_message(session, encrypted)
```

### `session`

Session management and key exchange operations.

```gleam
import libsignal_protocol_gleam/session

// Create new session
let session = session.new(identity_key_pair)

// Process pre-key bundle
let Ok(updated_session) = session.process_pre_key_bundle(session, bundle)

// Encrypt/decrypt messages
let Ok(encrypted) = session.encrypt(session, message)
let Ok(decrypted) = session.decrypt(session, encrypted)
```

### `pre_key_bundle`

Pre-key bundle handling and validation.

```gleam
import libsignal_protocol_gleam/pre_key_bundle

// Create pre-key bundle
let bundle = pre_key_bundle.new(identity_key, signed_pre_key, pre_keys)

// Validate bundle
case pre_key_bundle.validate(bundle) {
  Ok(bundle) -> // Bundle is valid
  Error(reason) -> // Bundle validation failed
}
```

### `utils`

Utility functions and type conversions.

```gleam
import libsignal_protocol_gleam/utils

// Convert between different key formats
let binary_key = utils.key_to_binary(key)
let key = utils.binary_to_key(binary_key)

// Validate key formats
let Ok(key) = utils.validate_key(binary_key)
```

## Error Handling

All functions return `Result` types for type-safe error handling:

```gleam
import gleam/result

case signal_protocol.generate_identity_key_pair() {
  Ok(#(public, private)) -> {
    // Success - use the keys
    io.println("Generated keys successfully")
  }
  Error(reason) -> {
    // Handle error
    io.println("Key generation failed: " <> reason)
  }
}
```

## Common Error Types

```gleam
pub type Error {
  InvalidParameters(String)
  KeyGenerationFailed(String)
  EncryptionFailed(String)
  DecryptionFailed(String)
  InvalidSession(String)
  InvalidSignature(String)
}
```

## Type Safety

This wrapper provides full type safety for all operations:

```gleam
// Keys are strongly typed
pub type IdentityKeyPair {
  IdentityKeyPair(PublicKey, PrivateKey)
}

pub type Session {
  Session(Binary)
}

// Functions have clear type signatures
pub fn generate_identity_key_pair() -> Result(IdentityKeyPair, Error)
pub fn encrypt_message(Session, String) -> Result(Binary, Error)
pub fn decrypt_message(Session, Binary) -> Result(String, Error)
```

## Performance

This wrapper uses the same high-performance C NIF implementation as the core library, providing:

- Native performance for cryptographic operations
- Efficient memory management
- Secure memory clearing
- Thread-safe operations

## Security

- All cryptographic operations use libsodium
- Sensitive data is automatically cleared from memory
- Keys are validated before use
- Signatures are verified for authenticity
- Type safety prevents many common security mistakes

## Documentation

For detailed documentation, see:

- [📚 Complete API Reference](../../docs/API.md)
- [🏗️ Architecture Guide](../../docs/ARCHITECTURE.md)
- [🔒 Security Considerations](../../docs/SECURITY.md)
- [📋 Documentation Plan](../../docs/DOCUMENTATION_PLAN.md)

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](../../CONTRIBUTING.md) for details.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](../../LICENSE) file for details.
