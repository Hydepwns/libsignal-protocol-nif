# libsignal-protocol-nif

Erlang NIF implementing the complete Signal Protocol with X3DH key agreement and Double Ratchet messaging.

## Status: ✅ COMPLETE

**Signal Protocol Implementation:**

- ✅ X3DH key agreement protocol
- ✅ Double Ratchet algorithm with forward/future secrecy
- ✅ Production-grade libsodium cryptography
- ✅ Comprehensive test suite

## Quick Start

```bash
nix-shell
./test/erl/final_deployment_test.erl
```

## Build

```bash
nix-shell --run "make clean && make"
```

## API

### X3DH Key Agreement

```erlang
{ok, {IdPub, IdPriv}} = libsignal_protocol_nif:generate_identity_key_pair(),
{ok, {PreKeyId, PreKeyPub}} = libsignal_protocol_nif:generate_pre_key(1),
{ok, {SignedId, SignedPub, Signature}} = libsignal_protocol_nif:generate_signed_pre_key(IdPriv, 1),
{ok, {SharedSecret, EphemeralPub}} = libsignal_protocol_nif:process_pre_key_bundle(IdPriv, Bundle).
```

### Double Ratchet Messaging

```erlang
{ok, Session} = libsignal_protocol_nif_v2:init_double_ratchet(SharedSecret, RemotePub, IsAlice),
{ok, {Encrypted, NewSession}} = libsignal_protocol_nif_v2:dr_encrypt_message(Session, Message),
{ok, {Decrypted, NewSession}} = libsignal_protocol_nif_v2:dr_decrypt_message(Session, Encrypted).
```

## Implementation

- **Cryptography**: Curve25519 ECDH, ChaCha20-Poly1305 AEAD, Ed25519 signatures
- **Session State**: 200 bytes per Double Ratchet session
- **Message Overhead**: 52 bytes (40-byte header + 12-byte nonce)
- **Security**: Forward secrecy, future secrecy, message authentication

## Documentation

See `docs/IMPLEMENTATION.md` for complete technical details.

## Requirements

- NixOS/Nix environment
- libsodium library
- AMD64 architecture
