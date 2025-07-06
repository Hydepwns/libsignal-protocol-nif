# Architecture Guide

This document provides a comprehensive overview of the libsignal-protocol-nif architecture, design decisions, and implementation details.

## Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Design Decisions](#design-decisions)
- [Memory Management](#memory-management)
- [Thread Safety](#thread-safety)
- [Error Handling](#error-handling)
- [Performance Considerations](#performance-considerations)
- [Security Architecture](#security-architecture)
- [Build System](#build-system)
- [Testing Architecture](#testing-architecture)
- [Future Considerations](#future-considerations)

## Overview

libsignal-protocol-nif is a high-performance Erlang NIF (Native Implemented Function) that provides Signal Protocol cryptographic primitives using libsodium. The architecture is designed for:

- **Performance**: Direct C implementation with minimal overhead
- **Security**: Secure memory management and cryptographic best practices
- **Reliability**: Comprehensive error handling and validation
- **Compatibility**: Cross-platform support with consistent behavior
- **Extensibility**: Modular design for future cryptographic operations

## System Architecture

### High-Level Architecture

```bash
┌─────────────────────────────────────────────────────────────┐
│                    Erlang/Elixir/Gleam                     │
│                     Application Layer                       │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                    NIF Interface Layer                      │
│              (erl_src/libsignal_protocol_nif.erl)          │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                    C NIF Implementation                     │
│              (c_src/libsignal_protocol_nif.c)              │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                    libsodium                                │
│              Cryptographic Library                          │
└─────────────────────────────────────────────────────────────┘
```

### Directory Structure

```bash
libsignal-protocol-nif/
├── c_src/                          # C NIF implementation
│   ├── libsignal_protocol_nif.c    # Main NIF entry points
│   ├── crypto/                     # Cryptographic operations
│   │   ├── crypto.c               # Core crypto functions
│   │   └── crypto.h               # Crypto function declarations
│   ├── keys/                      # Key management
│   │   ├── keys.c                 # Key generation and validation
│   │   └── keys.h                 # Key function declarations
│   ├── session/                   # Session management
│   │   ├── session.c              # Session operations
│   │   └── session.h              # Session function declarations
│   ├── utils/                     # Utility functions
│   │   ├── utils.c                # Common utilities
│   │   ├── utils.h                # Utility declarations
│   │   ├── error_handling.c       # Error handling utilities
│   │   └── error_handling.h       # Error handling declarations
│   ├── types.h                    # Common type definitions
│   ├── constants.h                # Cryptographic constants
│   └── CMakeLists.txt             # Build configuration
├── erl_src/                       # Erlang source code
│   ├── libsignal_protocol_nif.erl # Main Erlang module
│   └── signal_nif.erl             # Legacy interface
├── wrappers/                      # Language wrappers
│   ├── elixir/                    # Elixir wrapper
│   └── gleam/                     # Gleam wrapper
└── test/                          # Test suites
    ├── erl/                       # Erlang tests
    ├── elixir/                    # Elixir tests
    └── gleam/                     # Gleam tests
```

## Design Decisions

### 1. NIF vs Port Driver

**Decision**: Use NIFs instead of port drivers

**Rationale**:

- **Performance**: NIFs have lower overhead than port drivers
- **Simplicity**: Direct function calls without message passing
- **Memory Efficiency**: Shared memory between Erlang and C
- **Latency**: Synchronous execution without process communication

**Trade-offs**:

- **Blocking**: NIF calls block the Erlang scheduler
- **Crash Risk**: NIF crashes can bring down the entire VM
- **Complexity**: Manual memory management required

### 2. libsodium Integration

**Decision**: Use libsodium as the cryptographic backend

**Rationale**:

- **Security**: Well-audited, battle-tested cryptographic library
- **Performance**: Optimized implementations for various platforms
- **Completeness**: Provides all required Signal Protocol primitives
- **Maintenance**: Active development and security updates

**Benefits**:

- Curve25519 for ECDH key exchange
- Ed25519 for digital signatures
- AES-GCM for authenticated encryption
- SHA-256/512 for hashing
- HMAC-SHA256 for authentication

### 3. Error Handling Strategy

**Decision**: Return `{ok, Result}` or `{error, Reason}` tuples

**Rationale**:

- **Consistency**: Follows Erlang conventions
- **Clarity**: Explicit success/failure indication
- **Pattern Matching**: Natural fit with Erlang's pattern matching
- **Composability**: Easy to chain operations

**Implementation**:

```c
// C side: Return Erlang terms
static ERL_NIF_TERM generate_curve25519_keypair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    // ... implementation ...
    if (success) {
        return enif_make_tuple2(env, enif_make_atom(env, "ok"), result);
    } else {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), reason);
    }
}
```

### 4. Memory Management Strategy

**Decision**: Manual memory management with secure clearing

**Rationale**:

- **Security**: Sensitive data must be cleared from memory
- **Control**: Precise control over memory allocation/deallocation
- **Performance**: Avoid garbage collection overhead for sensitive data
- **Reliability**: Predictable memory usage patterns

**Implementation**:

```c
// Allocate memory for sensitive data
unsigned char *key = enif_alloc(32);
if (!key) {
    return enif_make_tuple2(env, enif_make_atom(env, "error"),
                           enif_make_atom(env, "memory_allocation_failed"));
}

// Use the memory
sodium_crypto_box_keypair(public_key, key);

// Clear sensitive data before freeing
sodium_memzero(key, 32);
enif_free(key);
```

## Memory Management

### Allocation Strategy

1. **Sensitive Data Allocation**:

   - Use `enif_alloc()` for sensitive data (keys, plaintext)
   - Always check allocation success
   - Clear memory with `sodium_memzero()` before freeing

2. **Binary Data Handling**:

   - Use `enif_make_binary()` for returning data to Erlang
   - Let Erlang's garbage collector handle binary cleanup
   - Avoid unnecessary copying when possible

3. **Temporary Buffers**:
   - Use stack allocation for small, temporary buffers
   - Use heap allocation for larger buffers
   - Always clear sensitive temporary data

### Memory Safety

```c
// Safe memory allocation pattern
static ERL_NIF_TERM safe_key_generation(ErlNifEnv *env)
{
    unsigned char *private_key = NULL;
    unsigned char *public_key = NULL;
    ERL_NIF_TERM result;

    // Allocate memory
    private_key = enif_alloc(32);
    public_key = enif_alloc(32);

    if (!private_key || !public_key) {
        // Clean up on allocation failure
        if (private_key) {
            sodium_memzero(private_key, 32);
            enif_free(private_key);
        }
        if (public_key) {
            enif_free(public_key);
        }
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "memory_allocation_failed"));
    }

    // Generate keys
    if (sodium_crypto_box_keypair(public_key, private_key) != 0) {
        // Clean up on generation failure
        sodium_memzero(private_key, 32);
        enif_free(private_key);
        enif_free(public_key);
        return enif_make_tuple2(env, enif_make_atom(env, "error"),
                               enif_make_atom(env, "key_generation_failed"));
    }

    // Create result
    ERL_NIF_TERM public_bin = enif_make_binary(env, &public_key_bin);
    ERL_NIF_TERM private_bin = enif_make_binary(env, &private_key_bin);

    // Clear sensitive data
    sodium_memzero(private_key, 32);
    enif_free(private_key);
    enif_free(public_key);

    return enif_make_tuple2(env, enif_make_atom(env, "ok"),
                           enif_make_tuple2(env, public_bin, private_bin));
}
```

## Thread Safety

### NIF Thread Safety

**Design**: All NIF functions are thread-safe

**Implementation**:

- **No Global State**: Functions are stateless and pure
- **libsodium Thread Safety**: libsodium functions are thread-safe
- **Memory Isolation**: Each call uses its own memory allocation
- **No Shared Resources**: No shared data structures between calls

### Erlang Scheduler Integration

**Behavior**:

- NIF calls run on the calling Erlang scheduler
- Long-running NIF calls block the scheduler
- Multiple schedulers can call NIFs concurrently
- No additional synchronization required

**Best Practices**:

- Keep NIF calls short and efficient
- Avoid blocking operations in NIFs
- Use dirty schedulers for long-running operations if needed

## Error Handling

### Error Categories

1. **Input Validation Errors**:

   - Invalid parameter types
   - Incorrect binary sizes
   - Null or empty parameters

2. **Cryptographic Errors**:

   - Key generation failures
   - Signature verification failures
   - Encryption/decryption failures

3. **System Errors**:
   - Memory allocation failures
   - libsodium initialization failures
   - Platform-specific errors

### Error Reporting

```c
// Consistent error reporting pattern
static ERL_NIF_TERM report_error(ErlNifEnv *env, const char *error_type, const char *details)
{
    ERL_NIF_TERM error_atom = enif_make_atom(env, error_type);
    ERL_NIF_TERM details_term = enif_make_string(env, details, ERL_NIF_LATIN1);
    return enif_make_tuple2(env, enif_make_atom(env, "error"),
                           enif_make_tuple2(env, error_atom, details_term));
}

// Usage
if (key_size != 32) {
    return report_error(env, "invalid_key_size", "Key must be 32 bytes");
}
```

### Error Recovery

**Strategy**: Fail fast with clear error messages

**Rationale**:

- **Security**: Cryptographic errors should not be recoverable
- **Clarity**: Clear error messages help debugging
- **Reliability**: Consistent error handling across all functions

## Performance Considerations

### Optimization Strategies

1. **Minimal Memory Allocation**:

   - Reuse buffers when possible
   - Use stack allocation for small data
   - Avoid unnecessary copying

2. **Efficient Binary Handling**:

   - Use `enif_inspect_binary()` for input validation
   - Use `enif_make_binary()` for output creation
   - Minimize binary copying

3. **libsodium Optimization**:
   - Use optimized libsodium functions
   - Leverage platform-specific optimizations
   - Use appropriate key sizes for performance

### Benchmarking

**Performance Targets**:

- Curve25519 key generation: < 100μs
- Ed25519 signature: < 200μs
- AES-GCM encryption (1KB): < 50μs
- SHA-256 (1KB): < 20μs

**Measurement**:

- Use Erlang's `timer:tc/1` for timing
- Measure memory usage with `erlang:memory/0`
- Profile with `eprof` or `fprof`

## Security Architecture

### Cryptographic Security

1. **Key Generation**:

   - Use libsodium's secure random number generator
   - Validate key sizes and formats
   - Clear sensitive data from memory

2. **Signature Verification**:

   - Use constant-time comparison
   - Validate signature lengths
   - Check public key formats

3. **Encryption**:
   - Use authenticated encryption (AES-GCM)
   - Validate IV sizes and uniqueness
   - Check tag lengths

### Memory Security

1. **Sensitive Data Handling**:

   - Clear all sensitive data with `sodium_memzero()`
   - Use secure memory allocation
   - Avoid logging sensitive data

2. **Input Validation**:

   - Validate all input parameters
   - Check binary sizes and formats
   - Reject malformed inputs

3. **Error Handling**:
   - Don't leak sensitive information in error messages
   - Use consistent error reporting
   - Fail securely on errors

## Build System

### CMake Configuration

```cmake
# CMakeLists.txt structure
cmake_minimum_required(VERSION 3.10)
project(libsignal_protocol_nif)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# Set compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

# Platform-specific settings
if(APPLE)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -undefined dynamic_lookup")
endif()

# Build shared library
add_library(libsignal_protocol_nif SHARED
    libsignal_protocol_nif.c
    crypto/crypto.c
    keys/keys.c
    session/session.c
    utils/utils.c
    utils/error_handling.c
)

# Link libraries
target_link_libraries(libsignal_protocol_nif ${SODIUM_LIBRARIES})
target_include_directories(libsignal_protocol_nif PRIVATE ${SODIUM_INCLUDE_DIRS})
```

### Cross-Platform Support

**Supported Platforms**:

- Linux (x86_64, ARM64)
- macOS (x86_64, ARM64)
- Windows (x86_64)

**Build Requirements**:

- CMake 3.10+
- libsodium development headers
- C compiler (GCC, Clang, MSVC)

## Testing Architecture

### Test Organization

```
test/
├── erl/                          # Erlang tests
│   ├── unit/                     # Unit tests
│   │   ├── crypto/               # Cryptographic function tests
│   │   ├── keys/                 # Key management tests
│   │   └── session/              # Session management tests
│   ├── integration/              # Integration tests
│   └── performance/              # Performance tests
├── elixir/                       # Elixir wrapper tests
└── gleam/                        # Gleam wrapper tests
```

### Test Categories

1. **Unit Tests**:

   - Individual function testing
   - Input validation testing
   - Error condition testing

2. **Integration Tests**:

   - End-to-end workflow testing
   - Cross-language compatibility testing
   - Performance regression testing

3. **Security Tests**:
   - Cryptographic correctness testing
   - Memory safety testing
   - Input validation testing

### Test Coverage

**Target Coverage**: 90%+ for all critical paths

**Coverage Areas**:

- All public API functions
- Error handling paths
- Memory management paths
- Input validation paths

## Future Considerations

### Planned Enhancements

1. **Additional Cryptographic Primitives**:

   - ChaCha20-Poly1305 encryption
   - Argon2 password hashing
   - X25519 key exchange variants

2. **Performance Optimizations**:

   - SIMD optimizations for supported platforms
   - Batch operations for multiple keys
   - Async operations for long-running tasks

3. **Security Enhancements**:
   - Hardware acceleration support
   - Side-channel attack mitigations
   - Formal verification of critical paths

### Architecture Evolution

1. **Modular Design**:

   - Plugin architecture for new primitives
   - Configurable cryptographic backends
   - Extensible error handling

2. **Performance Monitoring**:

   - Built-in performance metrics
   - Memory usage tracking
   - Cryptographic operation timing

3. **Developer Experience**:
   - Enhanced debugging support
   - Better error messages
   - Development tools and utilities

## Conclusion

The libsignal-protocol-nif architecture is designed for performance, security, and reliability. The modular design allows for easy extension while maintaining the core principles of secure cryptographic operations and efficient memory management.

Key architectural decisions include:

- **NIF-based implementation** for performance
- **libsodium integration** for security
- **Manual memory management** for control
- **Thread-safe design** for concurrency
- **Comprehensive error handling** for reliability

The architecture supports the current Signal Protocol requirements while providing a foundation for future enhancements and optimizations.
