# libsignal-protocol-elixir

Elixir wrapper for Signal Protocol NIF with OpenSSL 3.0+ compatibility.

## Installation

```elixir
def deps do
  [{:libsignal_protocol, "~> 0.1.0"}]
end
```

## Quick Start

```elixir
# Generate keys
{:ok, {public_key, signature}} = SignalProtocol.generate_identity_key_pair()
{:ok, {key_id, pre_key}} = SignalProtocol.generate_pre_key(1)

# Create session
{:ok, session} = SignalProtocol.create_session(local_key, remote_key)

# Encrypt/decrypt
{:ok, encrypted} = SignalProtocol.encrypt_message(session, "Hello")
{:ok, decrypted} = SignalProtocol.decrypt_message(session, encrypted)
```

## API

### SignalProtocol

- `generate_identity_key_pair()` → `{:ok, {public_key, signature}}`
- `generate_pre_key(id)` → `{:ok, {id, public_key}}`
- `generate_signed_pre_key(identity_key, id)` → `{:ok, {id, public_key, signature}}`
- `create_session(local, remote)` → `{:ok, session}`
- `encrypt_message(session, message)` → `{:ok, ciphertext}`
- `decrypt_message(session, ciphertext)` → `{:ok, plaintext}`

### SignalProtocol.Session

- `create(local, remote)` → `{:ok, session}`
- `send_message(session, message)` → `{:ok, ciphertext}`
- `receive_message(session, ciphertext)` → `{:ok, plaintext}`

### SignalProtocol.PreKeyBundle

- `create(reg_id, identity, pre_key, signed_pre_key, base_key)` → `{:ok, bundle}`
- `parse(bundle)` → `{:ok, bundle_data}`
- `verify_signature(bundle)` → `:ok`

## Build

```bash
cd wrappers/elixir
mix deps.get
mix compile
```

## Test

```bash
mix test
mix test --cover
```

## Requirements

- OpenSSL 3.0+
- Elixir 1.15+
- Erlang/OTP 25+

## License

MIT
