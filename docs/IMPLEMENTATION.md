# Cryptographic Primitives Implementation

## Status

Crypto Foundation Complete - Core cryptographic primitives implemented with libsodium

## Architecture

### Core Components

- **Key Generation**: Curve25519 and Ed25519 key pair generation
- **Digital Signatures**: Ed25519 signing and verification with proper key formatting
- **Hashing**: SHA-256 and SHA-512 implementations
- **Authentication**: HMAC-SHA256 with arbitrary key and data sizes
- **Encryption**: AES-GCM with configurable tag lengths and AAD

### Security Properties

- **Memory Safety**: Secure memory clearing with sodium_memzero()
- **Error Handling**: Comprehensive validation and error reporting
- **Key Format Compliance**: Proper 32-byte key sizes for all operations
- **Signature Format**: Standard 64-byte Ed25519 signatures

## API

### Key Generation Functions

```erlang
{ok, {PublicKey, PrivateKey}} = signal_nif:generate_curve25519_keypair()
{ok, {PublicKey, PrivateKey}} = signal_nif:generate_ed25519_keypair()
```

### Digital Signature Functions

```erlang
{ok, Signature} = signal_nif:sign_data(PrivateKey, Message)
ok = signal_nif:verify_signature(PublicKey, Message, Signature)
```

### Hashing Functions

```erlang
{ok, Hash} = signal_nif:sha256(Data)
{ok, Hash} = signal_nif:sha512(Data)
{ok, Hmac} = signal_nif:hmac_sha256(Key, Data)
```

### Encryption Functions

```erlang
{ok, Ciphertext, Tag} = signal_nif:aes_gcm_encrypt(Key, IV, Plaintext, AAD, TagLength)
{ok, Plaintext} = signal_nif:aes_gcm_decrypt(Key, IV, Ciphertext, AAD, Tag, PlaintextLength)
```

## Implementation Details

### Cryptographic Specifications

- **Curve25519**: X25519 ECDH with 32-byte keys
- **Ed25519**: Digital signatures with 32-byte public keys, 32-byte private keys, 64-byte signatures
- **SHA-256**: 32-byte output hashes
- **SHA-512**: 64-byte output hashes
- **HMAC-SHA256**: 32-byte authentication codes
- **AES-GCM**: Configurable tag lengths (12-16 bytes recommended)

### Key Format Details

- **Curve25519 Keys**: Raw 32-byte format for both public and private keys
- **Ed25519 Keys**: 32-byte public keys, 32-byte private keys (seed format)
- **Ed25519 Signatures**: Standard 64-byte signature format

### Error Handling

All functions return proper Erlang error tuples:

- `{ok, Result}` for successful operations
- `{error, Reason}` for failures
- `invalid_signature` for signature verification failures

## Testing

### Test Coverage

Complete test suite covering all implemented functions:

- Basic NIF functionality verification
- Key generation validation
- Signature creation and verification
- Hash function correctness
- HMAC authentication
- AES-GCM encryption/decryption round-trips

### Test Execution

```bash
nix-shell --run "rebar3 ct --suite=test/erl/unit/crypto/signal_crypto_SUITE.erl"
```

## Build Process

### Dependencies

- libsodium for cryptographic operations
- CMake for C compilation
- Erlang/OTP 27 for NIF interface

### Build Commands

```bash
nix-shell --run "make clean && make build"
```

### NIF Distribution

Automatic copying to all rebar3 test profile directories for comprehensive test coverage.

## Performance Characteristics

- **Key Generation**: Fast libsodium-optimized implementations
- **Signing**: Constant-time Ed25519 operations
- **Hashing**: Hardware-accelerated when available
- **Encryption**: AES-NI acceleration on supported platforms

## Security Considerations

- All sensitive data cleared with sodium_memzero()
- Constant-time operations for signature verification
- Proper random number generation via libsodium
- No custom cryptography - all operations delegated to libsodium
