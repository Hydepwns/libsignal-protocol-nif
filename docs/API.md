# API Reference

This document provides complete API documentation for the libsignal-protocol-nif library.

## Table of Contents

- [Core NIF Functions](#core-nif-functions)
- [Key Generation](#key-generation)
- [Digital Signatures](#digital-signatures)
- [Hashing and Authentication](#hashing-and-authentication)
- [Encryption](#encryption)
- [Session Management](#session-management)
- [Error Handling](#error-handling)
- [Data Types](#data-types)

## Core NIF Functions

### `signal_nif:init/0`

Initialize the Signal Protocol library.

**Returns:** `{ok, ok}` or `{error, Reason}`

**Example:**

```erlang
{ok, ok} = signal_nif:init().
```

**Error Reasons:**

- `libsodium_init_failed` - Failed to initialize libsodium

---

## Key Generation

### `signal_nif:generate_curve25519_keypair/0`

Generate a Curve25519 key pair for ECDH key exchange.

**Returns:** `{ok, {PublicKey, PrivateKey}}` or `{error, Reason}`

**Parameters:**

- `PublicKey` - 32-byte binary public key
- `PrivateKey` - 32-byte binary private key

**Example:**

```erlang
{ok, {PublicKey, PrivateKey}} = signal_nif:generate_curve25519_keypair(),
% PublicKey and PrivateKey are 32-byte binaries
```

**Error Reasons:**

- `key_generation_failed` - Cryptographic key generation failed
- `memory_allocation_failed` - Failed to allocate memory for keys

---

### `signal_nif:generate_ed25519_keypair/0`

Generate an Ed25519 key pair for digital signatures.

**Returns:** `{ok, {PublicKey, PrivateKey}}` or `{error, Reason}`

**Parameters:**

- `PublicKey` - 32-byte binary public key
- `PrivateKey` - 64-byte binary private key (includes public key)

**Example:**

```erlang
{ok, {PublicKey, PrivateKey}} = signal_nif:generate_ed25519_keypair(),
% PublicKey is 32 bytes, PrivateKey is 64 bytes
```

**Error Reasons:**

- `key_generation_failed` - Cryptographic key generation failed
- `memory_allocation_failed` - Failed to allocate memory for keys

---

## Digital Signatures

### `signal_nif:sign_data/2`

Sign data using Ed25519.

**Parameters:**

- `PrivateKey` - 64-byte Ed25519 private key
- `Message` - Binary message to sign

**Returns:** `{ok, Signature}` or `{error, Reason}`

**Parameters:**

- `Signature` - 64-byte binary signature

**Example:**

```erlang
{ok, {PublicKey, PrivateKey}} = signal_nif:generate_ed25519_keypair(),
Message = <<"Hello, World!">>,
{ok, Signature} = signal_nif:sign_data(PrivateKey, Message),
% Signature is 64 bytes
```

**Error Reasons:**

- `invalid_private_key` - Private key is invalid or wrong size
- `signature_failed` - Cryptographic signature operation failed
- `invalid_message` - Message is empty or invalid

---

### `signal_nif:verify_signature/3`

Verify an Ed25519 signature.

**Parameters:**

- `PublicKey` - 32-byte Ed25519 public key
- `Message` - Binary message that was signed
- `Signature` - 64-byte binary signature to verify

**Returns:** `ok` or `{error, Reason}`

**Example:**

```erlang
{ok, {PublicKey, PrivateKey}} = signal_nif:generate_ed25519_keypair(),
Message = <<"Hello, World!">>,
{ok, Signature} = signal_nif:sign_data(PrivateKey, Message),
ok = signal_nif:verify_signature(PublicKey, Message, Signature).
```

**Error Reasons:**

- `invalid_public_key` - Public key is invalid or wrong size
- `invalid_signature` - Signature is invalid or wrong size
- `signature_verification_failed` - Signature verification failed
- `invalid_message` - Message is empty or invalid

---

## Hashing and Authentication

### `signal_nif:sha256/1`

Compute SHA-256 hash of data.

**Parameters:**

- `Data` - Binary data to hash

**Returns:** `{ok, Hash}` or `{error, Reason}`

**Parameters:**

- `Hash` - 32-byte binary SHA-256 hash

**Example:**

```erlang
Data = <<"Hello, World!">>,
{ok, Hash} = signal_nif:sha256(Data),
% Hash is 32 bytes
```

**Error Reasons:**

- `hashing_failed` - Cryptographic hashing operation failed
- `invalid_data` - Data is empty or invalid

---

### `signal_nif:sha512/1`

Compute SHA-512 hash of data.

**Parameters:**

- `Data` - Binary data to hash

**Returns:** `{ok, Hash}` or `{error, Reason}`

**Parameters:**

- `Hash` - 64-byte binary SHA-512 hash

**Example:**

```erlang
Data = <<"Hello, World!">>,
{ok, Hash} = signal_nif:sha512(Data),
% Hash is 64 bytes
```

**Error Reasons:**

- `hashing_failed` - Cryptographic hashing operation failed
- `invalid_data` - Data is empty or invalid

---

### `signal_nif:hmac_sha256/2`

Compute HMAC-SHA256 authentication code.

**Parameters:**

- `Key` - Binary key for HMAC
- `Data` - Binary data to authenticate

**Returns:** `{ok, Hmac}` or `{error, Reason}`

**Parameters:**

- `Hmac` - 32-byte binary HMAC-SHA256

**Example:**

```erlang
Key = <<"secret_key">>,
Data = <<"Hello, World!">>,
{ok, Hmac} = signal_nif:hmac_sha256(Key, Data),
% Hmac is 32 bytes
```

**Error Reasons:**

- `hmac_failed` - HMAC computation failed
- `invalid_key` - Key is empty or invalid
- `invalid_data` - Data is empty or invalid

---

## Encryption

### `signal_nif:aes_gcm_encrypt/5`

Encrypt data using AES-GCM.

**Parameters:**

- `Key` - 16, 24, or 32-byte binary AES key
- `IV` - 12-byte binary initialization vector
- `Plaintext` - Binary data to encrypt
- `AAD` - Binary additional authenticated data (optional)
- `TagLength` - Integer length of authentication tag (12, 13, 14, 15, or 16)

**Returns:** `{ok, Ciphertext, Tag}` or `{error, Reason}`

**Parameters:**

- `Ciphertext` - Binary encrypted data
- `Tag` - Binary authentication tag

**Example:**

```erlang
Key = crypto:strong_rand_bytes(32),  % 32-byte AES-256 key
IV = crypto:strong_rand_bytes(12),   % 12-byte IV
Plaintext = <<"Hello, World!">>,
AAD = <<"metadata">>,
TagLength = 16,
{ok, Ciphertext, Tag} = signal_nif:aes_gcm_encrypt(Key, IV, Plaintext, AAD, TagLength).
```

**Error Reasons:**

- `invalid_key` - Key size is not 16, 24, or 32 bytes
- `invalid_iv` - IV size is not 12 bytes
- `invalid_tag_length` - Tag length is not 12-16 bytes
- `encryption_failed` - AES-GCM encryption failed
- `invalid_plaintext` - Plaintext is empty or invalid

---

### `signal_nif:aes_gcm_decrypt/6`

Decrypt data using AES-GCM.

**Parameters:**

- `Key` - 16, 24, or 32-byte binary AES key
- `IV` - 12-byte binary initialization vector
- `Ciphertext` - Binary encrypted data
- `AAD` - Binary additional authenticated data (optional)
- `Tag` - Binary authentication tag
- `PlaintextLength` - Integer expected length of plaintext

**Returns:** `{ok, Plaintext}` or `{error, Reason}`

**Parameters:**

- `Plaintext` - Binary decrypted data

**Example:**

```erlang
Key = crypto:strong_rand_bytes(32),
IV = crypto:strong_rand_bytes(12),
Plaintext = <<"Hello, World!">>,
AAD = <<"metadata">>,
TagLength = 16,
{ok, Ciphertext, Tag} = signal_nif:aes_gcm_encrypt(Key, IV, Plaintext, AAD, TagLength),
{ok, Decrypted} = signal_nif:aes_gcm_decrypt(Key, IV, Ciphertext, AAD, Tag, byte_size(Plaintext)),
% Decrypted should equal Plaintext
```

**Error Reasons:**

- `invalid_key` - Key size is not 16, 24, or 32 bytes
- `invalid_iv` - IV size is not 12 bytes
- `invalid_tag` - Tag is empty or invalid
- `decryption_failed` - AES-GCM decryption failed
- `authentication_failed` - Authentication tag verification failed
- `invalid_ciphertext` - Ciphertext is empty or invalid

---

## Session Management

### `signal_nif:create_session/2`

Create a new Signal Protocol session.

**Parameters:**

- `LocalPrivateKey` - 32-byte binary local private key
- `RemotePublicKey` - 32-byte binary remote public key

**Returns:** `{ok, Session}` or `{error, Reason}`

**Parameters:**

- `Session` - Binary session data

**Example:**

```erlang
{ok, {LocalPublic, LocalPrivate}} = signal_nif:generate_curve25519_keypair(),
{ok, {RemotePublic, _RemotePrivate}} = signal_nif:generate_curve25519_keypair(),
{ok, Session} = signal_nif:create_session(LocalPrivate, RemotePublic).
```

**Error Reasons:**

- `invalid_local_key` - Local private key is invalid
- `invalid_remote_key` - Remote public key is invalid
- `session_creation_failed` - Session creation failed

---

### `signal_nif:encrypt_message/2`

Encrypt a message using a session.

**Parameters:**

- `Session` - Binary session data
- `Message` - Binary message to encrypt

**Returns:** `{ok, EncryptedMessage}` or `{error, Reason}`

**Parameters:**

- `EncryptedMessage` - Binary encrypted message

**Example:**

```erlang
{ok, Session} = signal_nif:create_session(LocalPrivate, RemotePublic),
Message = <<"Hello, Signal!">>,
{ok, Encrypted} = signal_nif:encrypt_message(Session, Message).
```

**Error Reasons:**

- `invalid_session` - Session is invalid or corrupted
- `encryption_failed` - Message encryption failed
- `invalid_message` - Message is empty or invalid

---

### `signal_nif:decrypt_message/2`

Decrypt a message using a session.

**Parameters:**

- `Session` - Binary session data
- `EncryptedMessage` - Binary encrypted message

**Returns:** `{ok, Message}` or `{error, Reason}`

**Parameters:**

- `Message` - Binary decrypted message

**Example:**

```erlang
{ok, Session} = signal_nif:create_session(LocalPrivate, RemotePublic),
{ok, Encrypted} = signal_nif:encrypt_message(Session, Message),
{ok, Decrypted} = signal_nif:decrypt_message(Session, Encrypted).
```

**Error Reasons:**

- `invalid_session` - Session is invalid or corrupted
- `decryption_failed` - Message decryption failed
- `invalid_encrypted_message` - Encrypted message is invalid

---

## Error Handling

### Common Error Patterns

All functions follow a consistent error handling pattern:

```erlang
case signal_nif:some_function(Args) of
    {ok, Result} ->
        % Success - use Result
        handle_success(Result);
    {error, Reason} ->
        % Handle specific error
        handle_error(Reason)
end.
```

### Error Recovery

For cryptographic operations, errors are usually not recoverable:

```erlang
generate_keys() ->
    case signal_nif:generate_curve25519_keypair() of
        {ok, Keys} ->
            {ok, Keys};
        {error, key_generation_failed} ->
            % Retry once, then fail
            case signal_nif:generate_curve25519_keypair() of
                {ok, Keys} -> {ok, Keys};
                {error, _} -> {error, key_generation_failed}
            end;
        {error, Reason} ->
            {error, Reason}
    end.
```

### Input Validation

Always validate inputs before calling NIF functions:

```erlang
validate_key(Key) when is_binary(Key), byte_size(Key) =:= 32 ->
    {ok, Key};
validate_key(_) ->
    {error, invalid_key_size}.

safe_encrypt(Key, IV, Plaintext) ->
    case {validate_key(Key), validate_iv(IV), validate_plaintext(Plaintext)} of
        {{ok, ValidKey}, {ok, ValidIV}, {ok, ValidPlaintext}} ->
            signal_nif:aes_gcm_encrypt(ValidKey, ValidIV, ValidPlaintext, <<>>, 16);
        {Error, _, _} -> Error;
        {_, Error, _} -> Error;
        {_, _, Error} -> Error
    end.
```

---

## Data Types

### Binary Sizes

| Type                   | Size           | Description                                 |
| ---------------------- | -------------- | ------------------------------------------- |
| Curve25519 Public Key  | 32 bytes       | ECDH public key                             |
| Curve25519 Private Key | 32 bytes       | ECDH private key                            |
| Ed25519 Public Key     | 32 bytes       | Signature public key                        |
| Ed25519 Private Key    | 64 bytes       | Signature private key (includes public key) |
| Ed25519 Signature      | 64 bytes       | Digital signature                           |
| SHA-256 Hash           | 32 bytes       | SHA-256 hash output                         |
| SHA-512 Hash           | 64 bytes       | SHA-512 hash output                         |
| HMAC-SHA256            | 32 bytes       | HMAC authentication code                    |
| AES Key                | 16/24/32 bytes | AES-128/AES-192/AES-256 key                 |
| AES-GCM IV             | 12 bytes       | Initialization vector                       |
| AES-GCM Tag            | 12-16 bytes    | Authentication tag                          |

### Type Specifications

```erlang
-type curve25519_public_key() :: binary().  % 32 bytes
-type curve25519_private_key() :: binary(). % 32 bytes
-type ed25519_public_key() :: binary().     % 32 bytes
-type ed25519_private_key() :: binary().    % 64 bytes
-type ed25519_signature() :: binary().      % 64 bytes
-type sha256_hash() :: binary().            % 32 bytes
-type sha512_hash() :: binary().            % 64 bytes
-type hmac_sha256() :: binary().            % 32 bytes
-type aes_key() :: binary().                % 16, 24, or 32 bytes
-type aes_gcm_iv() :: binary().             % 12 bytes
-type aes_gcm_tag() :: binary().            % 12-16 bytes
-type session() :: binary().                % Session data
-type error_reason() :: atom() | string().
```

### Return Types

```erlang
-type key_pair() :: {curve25519_public_key(), curve25519_private_key()}.
-type ed25519_key_pair() :: {ed25519_public_key(), ed25519_private_key()}.
-type aes_gcm_result() :: {aes_gcm_ciphertext(), aes_gcm_tag()}.
-type result(T) :: {ok, T} | {error, error_reason()}.
```

---

## Performance Considerations

### Memory Management

- All sensitive data is automatically cleared from memory using `sodium_memzero()`
- Keys and sensitive data should be cleared from Erlang terms when no longer needed
- Large binary data should be garbage collected promptly

### Thread Safety

- All NIF functions are thread-safe
- Multiple Erlang processes can safely call NIF functions concurrently
- No additional synchronization is required

### Performance Tips

- Reuse sessions when possible to avoid key generation overhead
- Use appropriate key sizes (AES-256 for high security, AES-128 for performance)
- Batch operations when possible to reduce NIF call overhead

---

## Security Notes

### Key Management

- Never log or print private keys
- Store private keys securely (encrypted at rest)
- Rotate keys regularly
- Use secure random number generation for all keys

### Input Validation

- Always validate input sizes before calling NIF functions
- Check return values for all cryptographic operations
- Handle errors gracefully without exposing sensitive information

### Memory Security

- Sensitive data is automatically cleared from C memory
- Clear sensitive Erlang terms when no longer needed
- Avoid storing sensitive data in process dictionaries or ETS tables

---

## Examples

### Complete Key Exchange Example

```erlang
% Generate keys for Alice and Bob
{ok, {AlicePublic, AlicePrivate}} = signal_nif:generate_curve25519_keypair(),
{ok, {BobPublic, BobPrivate}} = signal_nif:generate_curve25519_keypair(),

% Create sessions
{ok, AliceSession} = signal_nif:create_session(AlicePrivate, BobPublic),
{ok, BobSession} = signal_nif:create_session(BobPrivate, AlicePublic),

% Alice sends encrypted message
Message = <<"Hello, Bob!">>,
{ok, Encrypted} = signal_nif:encrypt_message(AliceSession, Message),

% Bob decrypts message
{ok, Decrypted} = signal_nif:decrypt_message(BobSession, Encrypted),
% Decrypted should equal Message
```

### Digital Signature Example

```erlang
% Generate Ed25519 key pair
{ok, {PublicKey, PrivateKey}} = signal_nif:generate_ed25519_keypair(),

% Sign a message
Message = <<"Important document">>,
{ok, Signature} = signal_nif:sign_data(PrivateKey, Message),

% Verify signature
ok = signal_nif:verify_signature(PublicKey, Message, Signature).
```

### AES-GCM Encryption Example

```erlang
% Generate random key and IV
Key = crypto:strong_rand_bytes(32),
IV = crypto:strong_rand_bytes(12),

% Encrypt data
Plaintext = <<"Sensitive data">>,
AAD = <<"metadata">>,
{ok, Ciphertext, Tag} = signal_nif:aes_gcm_encrypt(Key, IV, Plaintext, AAD, 16),

% Decrypt data
{ok, Decrypted} = signal_nif:aes_gcm_decrypt(Key, IV, Ciphertext, AAD, Tag, byte_size(Plaintext)),
% Decrypted should equal Plaintext
```
