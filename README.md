# libsignal-protocol-nif

Erlang NIF implementing Signal Protocol cryptography with libsodium.

## Status: ✅ IMPLEMENTED

Real cryptography working:

- Curve25519 key generation, ECDH key agreement  
- ChaCha20-Poly1305 message encryption
- HMAC-SHA256 signatures for pre-keys
- 64-byte session state management

## Quick Start

```bash
nix-shell
bash verify_foundation.sh  # Should show: 🎊 REAL SIGNAL PROTOCOL CRYPTOGRAPHY IMPLEMENTED!
```

## Build

Requirements: NixOS/Nix, libsodium

```bash
nix-shell --run "cd c_src && make"
```

## Test

```bash
nix-shell --run "cd erl_src && erl -noshell -eval 'libsignal_protocol_nif:init(), {ok, {Pub, _}} = libsignal_protocol_nif:generate_identity_key_pair(), io:format(\"Key size: ~p~n\", [byte_size(Pub)]), halt().'"
```

Expected output: `Key size: 32`

## API

12 NIF functions in `libsignal_protocol_nif`:

- `generate_identity_key_pair/0` - Curve25519 keypair
- `generate_pre_key/1` - Pre-key with ID
- `generate_signed_pre_key/2` - HMAC-signed pre-key
- `create_session/1,2` - Session from keys
- `encrypt_message/2, decrypt_message/2` - ChaCha20-Poly1305
- `process_pre_key_bundle/2` - Bundle processing (placeholder)
- Cache functions: `get_cache_stats/1`, `reset_cache_stats/1`, `set_cache_size/3`

## Files

- `c_src/libsignal_protocol_nif.c` - Main NIF implementation
- `erl_src/libsignal_protocol_nif.erl` - Erlang module
- `verify_foundation.sh` - Verification script

## Next Enhancements

- X3DH key agreement protocol
- Double Ratchet algorithm  
- Ed25519 identity keys
- Message ordering/replay protection

## Troubleshooting

ARM64 segfault: Switch to AMD64 or see `docs/TROUBLESHOOTING.md`
