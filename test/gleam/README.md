# Signal Protocol for Gleam

This is the Gleam wrapper for the Signal Protocol implementation. It provides a type-safe and idiomatic Gleam interface to the Signal Protocol's secure messaging capabilities.

## Features

- Type-safe interface for Signal Protocol operations
- Comprehensive error handling
- Session management
- Pre-key bundle handling
- Message encryption and decryption
- Identity key management
- Utility functions for common operations

## Installation

Add the package to your `gleam.toml`:

```toml
[dependencies]
libsignal_protocol = { git = "https://github.com/hydepwns/libsignal-protocol-nif.git" }
```

## Usage

### Generating Keys

```gleam
import signal_protocol

// Generate an identity key pair
case signal_protocol.generate_identity_key_pair() {
  Ok(identity_key_pair) -> {
    // Use the identity key pair
    let public_key = identity_key_pair.public_key
    let signature = identity_key_pair.signature
  }
  Error(e) -> // Handle error
}

// Generate a pre-key
case signal_protocol.generate_pre_key(1) {
  Ok(pre_key) -> {
    // Use the pre-key
    let key_id = pre_key.key_id
    let public_key = pre_key.public_key
  }
  Error(e) -> // Handle error
}
```

### Managing Sessions

```gleam
import signal_protocol/session

// Create a new session
case session.create(local_identity_key, remote_identity_key) {
  Ok(session) -> {
    // Use the session
  }
  Error(e) -> // Handle error
}

// Encrypt a message
case session.encrypt_message(session, message) {
  Ok(ciphertext) -> {
    // Send the ciphertext
  }
  Error(e) -> // Handle error
}

// Decrypt a message
case session.decrypt_message(session, ciphertext) {
  Ok(message) -> {
    // Process the decrypted message
  }
  Error(e) -> // Handle error
}
```

### Working with Pre-Key Bundles

```gleam
import signal_protocol/pre_key_bundle

// Create a pre-key bundle
case pre_key_bundle.create(
  registration_id,
  identity_key,
  pre_key,
  signed_pre_key,
  base_key,
) {
  Ok(bundle) -> {
    // Use the bundle
  }
  Error(e) -> // Handle error
}

// Verify a bundle's signature
case pre_key_bundle.verify_signature(bundle) {
  Ok(Nil) -> {
    // Bundle is valid
  }
  Error(e) -> // Handle error
}
```

### Using Utility Functions

The library provides several utility functions to simplify common operations:

```gleam
import signal_protocol/utils

// Generate a complete set of keys for a new user
case utils.generate_user_keys() {
  Ok(#(identity_key_pair, pre_key, signed_pre_key)) -> {
    // Use the generated keys
  }
  Error(e) -> // Handle error
}

// Create a pre-key bundle from user keys
case utils.create_user_bundle(
  registration_id,
  identity_key_pair,
  pre_key,
  signed_pre_key,
) {
  Ok(bundle) -> {
    // Use the bundle
  }
  Error(e) -> // Handle error
}

// Establish a session between two users
case utils.establish_session(
  local_identity_key,
  local_registration_id,
  local_pre_key,
  local_signed_pre_key,
  remote_identity_key,
  remote_registration_id,
  remote_pre_key,
  remote_signed_pre_key,
) {
  Ok(#(local_session, remote_session)) -> {
    // Use the established sessions
  }
  Error(e) -> // Handle error
}

// Send a message and get the updated session
case utils.send_message_with_session(session, message) {
  Ok(#(ciphertext, new_session)) -> {
    // Send the ciphertext and use the new session
  }
  Error(e) -> // Handle error
}

// Receive a message and get the updated session
case utils.receive_message_with_session(session, ciphertext) {
  Ok(#(message, new_session)) -> {
    // Process the message and use the new session
  }
  Error(e) -> // Handle error
}

// Perform a complete message exchange
case utils.exchange_messages(local_session, remote_session, message) {
  Ok(#(received_message, new_local_session, new_remote_session)) -> {
    // Verify the exchange
    case utils.verify_message_exchange(message, received_message) {
      Ok(Nil) -> {
        // Message exchange successful
      }
      Error(e) -> // Handle verification error
    }
  }
  Error(e) -> // Handle exchange error
}
```

## Testing

Run the tests using:

```bash
gleam test
```
