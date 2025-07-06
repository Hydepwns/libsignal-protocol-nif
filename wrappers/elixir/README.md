# libsignal_protocol

[![Hex.pm](https://img.shields.io/hexpm/v/libsignal_protocol.svg)](https://hex.pm/packages/libsignal_protocol)
[![Hex.pm](https://img.shields.io/hexpm/dt/libsignal_protocol.svg)](https://hex.pm/packages/libsignal_protocol)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Elixir wrapper for Signal Protocol cryptographic primitives with libsodium.

This package provides idiomatic Elixir APIs for Signal Protocol operations, including key generation, digital signatures, encryption, and session management.

## Installation

Add `libsignal_protocol` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:libsignal_protocol, "~> 0.1.0"}
  ]
end
```

## Quick Start

```elixir
# Initialize the library
{:ok, _} = LibsignalProtocol.init()

# Generate identity key pair
{:ok, {public_key, private_key}} = SignalProtocol.generate_identity_key_pair()

# Generate pre-key
{:ok, {key_id, pre_key}} = SignalProtocol.generate_pre_key(1)

# Create session
{:ok, session} = SignalProtocol.create_session(public_key)

# Encrypt message
{:ok, encrypted} = SignalProtocol.encrypt_message(session, "Hello, Signal!")

# Decrypt message
{:ok, decrypted} = SignalProtocol.decrypt_message(session, encrypted)
```

## Available Modules

### `SignalProtocol`

Core cryptographic operations and key management.

```elixir
# Key generation
{:ok, {public, private}} = SignalProtocol.generate_identity_key_pair()
{:ok, {key_id, pre_key}} = SignalProtocol.generate_pre_key(1)
{:ok, {key_id, signed_pre_key}} = SignalProtocol.generate_signed_pre_key(private, 2)

# Session management
{:ok, session} = SignalProtocol.create_session(remote_public_key)
{:ok, session} = SignalProtocol.create_session(local_private_key, remote_public_key)

# Message encryption/decryption
{:ok, encrypted} = SignalProtocol.encrypt_message(session, message)
{:ok, decrypted} = SignalProtocol.decrypt_message(session, encrypted)
```

### `Session`

Session management and key exchange operations.

```elixir
# Create new session
session = Session.new(identity_key_pair)

# Process pre-key bundle
{:ok, updated_session} = Session.process_pre_key_bundle(session, bundle)

# Encrypt/decrypt messages
{:ok, encrypted} = Session.encrypt(session, message)
{:ok, decrypted} = Session.decrypt(session, encrypted)
```

### `PreKeyBundle`

Pre-key bundle handling and validation.

```elixir
# Create pre-key bundle
bundle = PreKeyBundle.new(identity_key, signed_pre_key, pre_keys)

# Validate bundle
case PreKeyBundle.validate(bundle) do
  {:ok, bundle} -> # Bundle is valid
  {:error, reason} -> # Bundle validation failed
end
```

### `LibsignalProtocol`

Main interface module providing high-level operations.

```elixir
# Initialize the library
{:ok, _} = LibsignalProtocol.init()

# Generate keys
{:ok, keys} = LibsignalProtocol.generate_keys()

# Create session
{:ok, session} = LibsignalProtocol.create_session(recipient_id)

# Send message
{:ok, encrypted} = LibsignalProtocol.encrypt_message(session, message)

# Receive message
{:ok, decrypted} = LibsignalProtocol.decrypt_message(session, encrypted)
```

## Error Handling

All functions return `{:ok, result}` on success or `{:error, reason}` on failure:

```elixir
case SignalProtocol.generate_identity_key_pair() do
  {:ok, {public, private}} ->
    # Success - use the keys
    IO.puts("Generated keys successfully")

  {:error, reason} ->
    # Handle error
    IO.puts("Key generation failed: #{reason}")
end
```

## Common Error Reasons

- `:invalid_parameters` - Invalid input parameters
- `:key_generation_failed` - Cryptographic key generation failed
- `:encryption_failed` - Message encryption failed
- `:decryption_failed` - Message decryption failed
- `:invalid_session` - Session state is invalid
- `:invalid_signature` - Digital signature verification failed

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
