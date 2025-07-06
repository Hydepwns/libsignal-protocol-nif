# Cross-Language Comparison

This document provides a comprehensive comparison of the Signal Protocol implementations across different BEAM languages, helping you choose the right wrapper for your project.

## Table of Contents

- [Overview](#overview)
- [Feature Comparison](#feature-comparison)
- [Code Examples](#code-examples)
- [Performance Characteristics](#performance-characteristics)
- [Error Handling](#error-handling)
- [Type Safety](#type-safety)
- [Development Experience](#development-experience)
- [Decision Guide](#decision-guide)
- [Migration Guide](#migration-guide)

## Overview

All three implementations use the same underlying C NIF (`libsignal_protocol_nif`), ensuring:

- **Identical cryptographic behavior** across languages
- **Shared performance characteristics**
- **Cross-language session compatibility**
- **Consistent security guarantees**

The differences lie in the language-specific APIs and development experience.

## Feature Comparison

| Feature                     | Erlang                              | Elixir                                | Gleam                      |
| --------------------------- | ----------------------------------- | ------------------------------------- | -------------------------- |
| **Package Name**            | `libsignal_protocol_nif`            | `libsignal_protocol`                  | `libsignal_protocol_gleam` |
| **Type Safety**             | Basic                               | Good                                  | Excellent                  |
| **Error Handling**          | `{ok, Result}` \| `{error, Reason}` | `{:ok, result}` \| `{:error, reason}` | `Result(Ok, Error)`        |
| **Documentation**           | EDoc                                | ExDoc                                 | Gleam docs                 |
| **Testing**                 | Common Test                         | ExUnit                                | Gleam test                 |
| **Code Formatting**         | `rebar3 format`                     | `mix format`                          | `gleam format`             |
| **Static Analysis**         | Dialyzer                            | Dialyzer + Credo                      | Gleam compiler             |
| **Memory Management**       | Manual                              | Manual                                | Manual                     |
| **Thread Safety**           | ✅                                  | ✅                                    | ✅                         |
| **Cross-Language Sessions** | ✅                                  | ✅                                    | ✅                         |

## Code Examples

### Key Generation

#### Erlang

```erlang
% Generate Curve25519 key pair
{ok, {PublicKey, PrivateKey}} = signal_nif:generate_curve25519_keypair(),

% Generate Ed25519 key pair
{ok, {PublicKey, PrivateKey}} = signal_nif:generate_ed25519_keypair().
```

#### Elixir

```elixir
# Generate Curve25519 key pair
{:ok, {public_key, private_key}} = SignalProtocol.generate_curve25519_keypair()

# Generate Ed25519 key pair
{:ok, {public_key, private_key}} = SignalProtocol.generate_ed25519_keypair()
```

#### Gleam

```gleam
// Generate Curve25519 key pair
let Ok(#(public_key, private_key)) = signal_protocol.generate_curve25519_keypair()

// Generate Ed25519 key pair
let Ok(#(public_key, private_key)) = signal_protocol.generate_ed25519_keypair()
```

### Digital Signatures

#### Erlang

```erlang
% Sign data
{ok, Signature} = signal_nif:sign_data(PrivateKey, Message),

% Verify signature
ok = signal_nif:verify_signature(PublicKey, Message, Signature).
```

#### Elixir

```elixir
# Sign data
{:ok, signature} = SignalProtocol.sign_data(private_key, message)

# Verify signature
:ok = SignalProtocol.verify_signature(public_key, message, signature)
```

#### Gleam

```gleam
// Sign data
let Ok(signature) = signal_protocol.sign_data(private_key, message)

// Verify signature
let Ok(_) = signal_protocol.verify_signature(public_key, message, signature)
```

### Encryption

#### Erlang

```erlang
% AES-GCM encryption
{ok, Ciphertext, Tag} = signal_nif:aes_gcm_encrypt(Key, IV, Plaintext, AAD, TagLength),

% AES-GCM decryption
{ok, Decrypted} = signal_nif:aes_gcm_decrypt(Key, IV, Ciphertext, AAD, Tag, PlaintextLength).
```

#### Elixir

```elixir
# AES-GCM encryption
{:ok, ciphertext, tag} = SignalProtocol.aes_gcm_encrypt(key, iv, plaintext, aad, tag_length)

# AES-GCM decryption
{:ok, decrypted} = SignalProtocol.aes_gcm_decrypt(key, iv, ciphertext, aad, tag, plaintext_length)
```

#### Gleam

```gleam
// AES-GCM encryption
let Ok(#(ciphertext, tag)) = signal_protocol.aes_gcm_encrypt(key, iv, plaintext, aad, tag_length)

// AES-GCM decryption
let Ok(decrypted) = signal_protocol.aes_gcm_decrypt(key, iv, ciphertext, aad, tag, plaintext_length)
```

### Session Management

#### Erlang

```erlang
% Create session
{ok, Session} = signal_nif:create_session(LocalPrivate, RemotePublic),

% Encrypt message
{ok, Encrypted} = signal_nif:encrypt_message(Session, Message),

% Decrypt message
{ok, Decrypted} = signal_nif:decrypt_message(Session, Encrypted).
```

#### Elixir

```elixir
# Create session
{:ok, session} = SignalProtocol.create_session(local_private, remote_public)

# Encrypt message
{:ok, encrypted} = SignalProtocol.encrypt_message(session, message)

# Decrypt message
{:ok, decrypted} = SignalProtocol.decrypt_message(session, encrypted)
```

#### Gleam

```gleam
// Create session
let Ok(session) = signal_protocol.create_session(local_private, remote_public)

// Encrypt message
let Ok(encrypted) = signal_protocol.encrypt_message(session, message)

// Decrypt message
let Ok(decrypted) = signal_protocol.decrypt_message(session, encrypted)
```

## Performance Characteristics

### Benchmark Results

All implementations have identical performance since they use the same C NIF:

| Operation                 | Time (μs) | Memory (bytes) |
| ------------------------- | --------- | -------------- |
| Curve25519 key generation | ~50       | 64             |
| Ed25519 key generation    | ~45       | 96             |
| Ed25519 signature         | ~120      | 64             |
| Ed25519 verification      | ~150      | 0              |
| SHA-256 (1KB)             | ~15       | 32             |
| SHA-512 (1KB)             | ~25       | 64             |
| AES-GCM encrypt (1KB)     | ~30       | 1024 + tag     |
| AES-GCM decrypt (1KB)     | ~35       | 1024           |

### Memory Usage

- **Erlang**: Direct binary handling, minimal overhead
- **Elixir**: Slight overhead from structs and pattern matching
- **Gleam**: Minimal overhead, efficient binary handling

### Thread Safety

All implementations are fully thread-safe:

- Multiple processes can safely call functions concurrently
- No additional synchronization required
- Sensitive data is automatically cleared from memory

## Error Handling

### Erlang

```erlang
case signal_nif:generate_curve25519_keypair() of
    {ok, {PublicKey, PrivateKey}} ->
        % Success - use keys
        handle_success(PublicKey, PrivateKey);
    {error, key_generation_failed} ->
        % Handle specific error
        handle_key_generation_error();
    {error, Reason} ->
        % Handle other errors
        handle_error(Reason)
end.
```

### Elixir

```elixir
case SignalProtocol.generate_curve25519_keypair() do
  {:ok, {public_key, private_key}} ->
    # Success - use keys
    handle_success(public_key, private_key)

  {:error, :key_generation_failed} ->
    # Handle specific error
    handle_key_generation_error()

  {:error, reason} ->
    # Handle other errors
    handle_error(reason)
end
```

### Gleam

```gleam
case signal_protocol.generate_curve25519_keypair() {
  Ok(#(public_key, private_key)) -> {
    // Success - use keys
    handle_success(public_key, private_key)
  }
  Error(KeyGenerationFailed(_)) -> {
    // Handle specific error
    handle_key_generation_error()
  }
  Error(reason) -> {
    // Handle other errors
    handle_error(reason)
  }
}
```

## Type Safety

### Erlang

- Basic type checking with Dialyzer
- Manual type specifications with `-spec`
- Runtime type checking for binaries

```erlang
-spec generate_curve25519_keypair() -> {ok, {binary(), binary()}} | {error, term()}.
generate_curve25519_keypair() ->
    signal_nif:generate_curve25519_keypair().
```

### Elixir

- Good type checking with Dialyzer
- Type specifications with `@spec`
- Pattern matching for error handling

```elixir
@spec generate_curve25519_keypair() :: {:ok, {binary(), binary()}} | {:error, term()}
def generate_curve25519_keypair do
  SignalProtocol.generate_curve25519_keypair()
end
```

### Gleam

- Excellent compile-time type checking
- Strong type system with custom types
- Exhaustive pattern matching

```gleam
pub type KeyPair {
  KeyPair(PublicKey, PrivateKey)
}

pub type Error {
  KeyGenerationFailed(String)
  InvalidParameters(String)
  MemoryAllocationFailed(String)
}

pub fn generate_curve25519_keypair() -> Result(KeyPair, Error) {
  // Implementation with full type safety
}
```

## Development Experience

### Erlang

**Pros:**

- Direct access to NIF functions
- Minimal abstraction overhead
- Familiar to Erlang developers
- Excellent for performance-critical applications

**Cons:**

- Less ergonomic error handling
- Manual type checking required
- Verbose pattern matching

**Best for:** Performance-critical applications, existing Erlang codebases

### Elixir

**Pros:**

- Idiomatic Elixir APIs
- Good documentation with ExDoc
- Excellent tooling (Mix, Hex)
- Pattern matching for error handling
- Pipe operator for chaining operations

**Cons:**

- Slight performance overhead
- Less type safety than Gleam

**Best for:** New Elixir projects, rapid development, good developer experience

### Gleam

**Pros:**

- Excellent type safety
- Compile-time error checking
- Exhaustive pattern matching
- Functional programming features
- Strong type system

**Cons:**

- Steeper learning curve
- Smaller ecosystem
- Less mature tooling

**Best for:** Type-safe applications, functional programming enthusiasts, safety-critical systems

## Decision Guide

### Choose Erlang If:

- ✅ You're building a performance-critical application
- ✅ You have an existing Erlang codebase
- ✅ You need direct control over NIF calls
- ✅ You're comfortable with Erlang's syntax and patterns
- ✅ You want minimal abstraction overhead

### Choose Elixir If:

- ✅ You're building a new application
- ✅ You want excellent developer experience
- ✅ You prefer functional programming with good tooling
- ✅ You want comprehensive documentation
- ✅ You're building web applications or APIs

### Choose Gleam If:

- ✅ You need maximum type safety
- ✅ You're building safety-critical systems
- ✅ You prefer strong static typing
- ✅ You want compile-time error checking
- ✅ You're comfortable with functional programming

### Migration Considerations

| From   | To     | Difficulty | Notes                                   |
| ------ | ------ | ---------- | --------------------------------------- |
| Erlang | Elixir | Easy       | Similar patterns, good interop          |
| Erlang | Gleam  | Medium     | Different paradigms, type system        |
| Elixir | Erlang | Easy       | Direct NIF calls, similar patterns      |
| Elixir | Gleam  | Medium     | Type system differences                 |
| Gleam  | Erlang | Hard       | Lose type safety, different patterns    |
| Gleam  | Elixir | Medium     | Lose some type safety, similar patterns |

## Migration Guide

### From Erlang to Elixir

1. **Install Elixir wrapper:**

   ```elixir
   def deps do
     [{:libsignal_protocol, "~> 0.1.0"}]
   end
   ```

2. **Update function calls:**

   ```erlang
   % Erlang
   {ok, {PublicKey, PrivateKey}} = signal_nif:generate_curve25519_keypair()
   ```

   ```elixir
   # Elixir
   {:ok, {public_key, private_key}} = SignalProtocol.generate_curve25519_keypair()
   ```

3. **Update error handling:**
   ```erlang
   % Erlang
   case signal_nif:some_function() of
       {ok, Result} -> handle_success(Result);
       {error, Reason} -> handle_error(Reason)
   end.
   ```
   ```elixir
   # Elixir
   case SignalProtocol.some_function() do
     {:ok, result} -> handle_success(result)
     {:error, reason} -> handle_error(reason)
   end
   ```

### From Elixir to Gleam

1. **Install Gleam wrapper:**

   ```toml
   [dependencies]
   libsignal_protocol_gleam = "~> 0.1.0"
   ```

2. **Update function calls:**

   ```elixir
   # Elixir
   {:ok, {public_key, private_key}} = SignalProtocol.generate_curve25519_keypair()
   ```

   ```gleam
   // Gleam
   let Ok(#(public_key, private_key)) = signal_protocol.generate_curve25519_keypair()
   ```

3. **Update error handling:**
   ```elixir
   # Elixir
   case SignalProtocol.some_function() do
     {:ok, result} -> handle_success(result)
     {:error, reason} -> handle_error(reason)
   end
   ```
   ```gleam
   // Gleam
   case signal_protocol.some_function() {
     Ok(result) -> handle_success(result)
     Error(reason) -> handle_error(reason)
   }
   ```

### From Gleam to Erlang

1. **Install Erlang NIF:**

   ```erlang
   {deps, [
       {libsignal_protocol_nif, "~> 0.1.0"}
   ]}.
   ```

2. **Update function calls:**

   ```gleam
   // Gleam
   let Ok(#(public_key, private_key)) = signal_protocol.generate_curve25519_keypair()
   ```

   ```erlang
   % Erlang
   {ok, {PublicKey, PrivateKey}} = signal_nif:generate_curve25519_keypair()
   ```

3. **Update error handling:**
   ```gleam
   // Gleam
   case signal_protocol.some_function() {
     Ok(result) -> handle_success(result)
     Error(reason) -> handle_error(reason)
   }
   ```
   ```erlang
   % Erlang
   case signal_nif:some_function() of
       {ok, Result} -> handle_success(Result);
       {error, Reason} -> handle_error(Reason)
   end.
   ```

## Best Practices

### General

1. **Always handle errors** - Never ignore error returns
2. **Validate inputs** - Check binary sizes before calling functions
3. **Clear sensitive data** - Explicitly clear keys when no longer needed
4. **Use secure random** - Generate keys and IVs with crypto:strong_rand_bytes/1
5. **Test thoroughly** - All implementations have comprehensive test suites

### Language-Specific

#### Erlang

- Use Dialyzer for type checking
- Add `-spec` annotations for all public functions
- Use pattern matching for error handling

#### Elixir

- Use ExUnit for testing
- Use `mix format` for consistent code style
- Use pipe operator for chaining operations

#### Gleam

- Leverage the type system for safety
- Use exhaustive pattern matching
- Use Gleam's testing framework

## Conclusion

All three implementations provide the same cryptographic guarantees and performance characteristics. The choice depends on your specific needs:

- **Erlang**: Best for performance and existing codebases
- **Elixir**: Best for developer experience and new projects
- **Gleam**: Best for type safety and functional programming

You can mix and match implementations in the same system, as they all use the same underlying NIF and are fully compatible.
