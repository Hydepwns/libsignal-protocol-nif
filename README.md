# libsignal-protocol-nif

Cross-platform BEAM wrappers (Erlang/Elixir/Gleam) for the Signal Protocol library, implemented with OpenSSL cryptographic primitives.

## About The Project

A modern, cross-platform BEAM (Erlang/Elixir/Gleam) implementation of the Signal Protocol, providing secure end-to-end encryption capabilities using OpenSSL.

- **Erlang NIF API**: Low-level, direct access to Signal Protocol from Erlang
- **Elixir wrapper**: Ergonomic, idiomatic Elixir API for secure messaging
- **Gleam wrapper**: Type-safe, functional API for Gleam projects

## Features

- End-to-end encryption using Signal Protocol
- Session management
- Pre-key bundle handling
- Message encryption/decryption
- Key exchange
- Perfect forward secrecy
- Cross-platform support (Linux, macOS, Windows)
- OpenSSL-based cryptographic primitives
- C implementation with NIF interface

## Project Structure

```bash
libsignal-protocol-nif/
├── c_src/              # C source files and NIF implementation
│   ├── crypto/        # Cryptographic primitives
│   ├── protocol/      # Signal Protocol implementation
│   ├── nif/          # NIF interface
│   └── cmake/        # CMake configuration
├── src/               # Erlang source files
├── lib/               # Additional Erlang modules
├── include/           # Type definitions
├── test/              # Test files
├── wrappers/          # Language-specific wrappers
│   ├── elixir/       # Elixir wrapper
│   └── gleam/        # Gleam wrapper
├── scripts/           # Build and release scripts
├── docker-compose.yml # Containerized testing
├── Dockerfile         # Multi-stage Docker build
└── .vscode/          # VS Code configuration
```

## Prerequisites

- Erlang/OTP 22+
- `make`
- C compiler (GCC/Clang)
- CMake 3.10+

### Platform-Specific Requirements

#### macOS

```bash
xcode-select --install
```

#### Ubuntu/Debian

```bash
sudo apt-get install build-essential cmake
```

#### Windows

- Visual Studio 2019 or later
- CMake

## Installation

### Erlang

Add to your `rebar.config`:

```erlang
{deps, [
  {libsignal_protocol_nif, {git, "https://github.com/Hydepwns/libsignal-protocol-nif.git"}}
]}.
```

### Elixir

Add to your `mix.exs`:

```elixir
def deps do
  [
    {:libsignal_protocol, "~> 0.1.0"}
  ]
end
```

### Gleam

See `wrappers/gleam/README.md` for full instructions.

## Usage

### Erlang Quickstart

```erlang
% Initialize the library
ok = libsignal_protocol_nif:init(),

% Generate identity key pair
{ok, {PublicKey, PrivateKey}} = libsignal_protocol_nif:generate_identity_key_pair(),

% Create a new session (requires both local and remote identity keys)
{ok, Session} = libsignal_protocol_nif:create_session(LocalIdentityKey, RemoteIdentityKey),

% Encrypt a message
{ok, Encrypted} = libsignal_protocol_nif:encrypt_message(Session, "Hello, Signal!"),

% Decrypt a message
{ok, Decrypted} = libsignal_protocol_nif:decrypt_message(Session, Encrypted).
```

### Elixir Quickstart

```elixir
# Start the Signal Protocol process
{:ok, pid} = SignalProtocol.start_link()

# Generate identity key pair
{:ok, {public_key, signature}} = SignalProtocol.generate_identity_key_pair()

# Create a new session (requires both local and remote identity keys)
{:ok, session} = SignalProtocol.create_session(local_identity_key, remote_identity_key)

# Encrypt a message
{:ok, encrypted} = SignalProtocol.encrypt_message(session, "Hello, Signal!")

# Decrypt a message
{:ok, decrypted} = SignalProtocol.decrypt_message(session, encrypted)
```

### Gleam Quickstart

```gleam
import libsignal_protocol_gleam

pub fn main() {
  case libsignal_protocol_gleam.init() {
    Ok(_) -> {
      case libsignal_protocol_gleam.generate_identity_key_pair() {
        Ok(identity_pair) -> {
          case libsignal_protocol_gleam.create_session(
            local_identity_key,
            remote_identity_key
          ) {
            Ok(session) -> {
              case libsignal_protocol_gleam.encrypt_message(session, "Hello, Signal!") {
                Ok(encrypted) -> {
                  case libsignal_protocol_gleam.decrypt_message(session, encrypted) {
                    Ok(decrypted) -> {
                      // Use decrypted message
                    }
                    Error(e) -> {
                      // Handle error
                    }
                  }
                }
                Error(e) -> {
                  // Handle error
                }
              }
            }
            Error(e) -> {
              // Handle error
            }
          }
        }
        Error(e) -> {
          // Handle error
        }
      }
    }
    Error(e) -> {
      // Handle error
    }
  }
}
```

## Building

### Unified Build (Recommended)

```bash
make build      # Build everything (C, Erlang, Elixir, Gleam)
make test       # Run all tests
make clean      # Clean all build artifacts
```

### Platform-Specific Build

```bash
# Linux/macOS
make build

# Windows
make build
```

## Testing

```bash
make test              # Run all tests
make test-cover        # Run tests with coverage
make perf-test         # Run performance benchmarks
```

## Docker Support

```bash
make docker-build      # Build Docker images
make docker-test       # Run tests in Docker
make docker-perf       # Run performance tests in Docker
```

## Development

```bash
make dev-setup         # Setup development environment
make dev-test          # Run all development tests
make docs              # Generate documentation
```

## Security

This implementation:

- Uses OpenSSL for cryptographic primitives
- Implements Signal Protocol specifications exactly
- Includes comprehensive security testing
- Provides perfect forward secrecy
- Implements proper key rotation
- Uses secure memory handling

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Signal Protocol team for the protocol specification
- BEAM community for NIF documentation and examples
- Contributors and maintainers of the project
