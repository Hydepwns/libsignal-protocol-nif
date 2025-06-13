# libsignal-protocol-nif

Cross-platform BEAM wrappers (Erlang/Elixir/Gleam) for the Signal Protocol library, implemented from scratch without external dependencies.

## About The Project

A modern, cross-platform BEAM (Erlang/Elixir/Gleam) implementation of the Signal Protocol, providing secure end-to-end encryption capabilities without external dependencies.

* **Erlang NIF API**: Low-level, direct access to Signal Protocol from Erlang
* **Elixir wrapper**: Ergonomic, idiomatic Elixir API for secure messaging
* **Gleam wrapper**: Type-safe, functional API for Gleam projects

## Features

- End-to-end encryption using Signal Protocol
- Session management
- Pre-key bundle handling
- Message encryption/decryption
- Key exchange
- Perfect forward secrecy
- Cross-platform support (Linux, macOS, Windows)
- No external dependencies
- Pure C implementation of cryptographic primitives

## Project Structure

```
libsignal-protocol-nif/
├── c_src/              # C source files and NIF implementation
│   ├── crypto/        # Cryptographic primitives
│   ├── protocol/      # Signal Protocol implementation
│   └── nif/          # NIF interface
├── src/               # Erlang source files
├── test/              # Test files
├── wrappers/          # Language-specific wrappers
│   ├── elixir/       # Elixir wrapper
│   └── gleam/        # Gleam wrapper
└── .vscode/          # VS Code configuration
```

## Prerequisites

* Erlang/OTP 22+
* `make`
* C compiler (GCC/Clang)

### Platform-Specific Requirements

#### macOS
```bash
xcode-select --install
```

#### Ubuntu/Debian
```bash
sudo apt-get install build-essential
```

#### Windows
* Visual Studio 2019 or later
* CMake

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
    {:libsignal_protocol_nif, "~> 0.1.0"}
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

% Create a new session
{ok, Session} = libsignal_protocol_nif:create_session(RecipientId),

% Encrypt a message
{ok, Encrypted} = libsignal_protocol_nif:encrypt_message(Session, "Hello, Signal!"),

% Decrypt a message
{ok, Decrypted} = libsignal_protocol_nif:decrypt_message(Session, Encrypted).
```

### Elixir Quickstart

```elixir
# Initialize the library
:ok = LibsignalProtocol.init()

# Create a new session
{:ok, session} = LibsignalProtocol.create_session(recipient_id)

# Encrypt a message
{:ok, encrypted} = LibsignalProtocol.encrypt_message(session, "Hello, Signal!")

# Decrypt a message
{:ok, decrypted} = LibsignalProtocol.decrypt_message(session, encrypted)
```

### Gleam Quickstart

```gleam
import libsignal_protocol_gleam

pub fn main() {
  case libsignal_protocol_gleam.init() {
    Ok(_) -> {
      case libsignal_protocol_gleam.create_session(recipient_id) {
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
```

## Building

### Unified Build (Recommended)

```bash
make build      # Build everything (C, Erlang, Elixir, Gleam)
make test       # Run all tests
make clean-all  # Clean all build artifacts
```

### Platform-Specific Build

```bash
# Linux/macOS
make build

# Windows
make build-windows
```

## Testing

```bash
make test              # Run all tests
make test-erlang      # Run Erlang tests
make test-elixir      # Run Elixir tests
make test-gleam       # Run Gleam tests
```

## Security

This implementation:
- Uses no external cryptographic libraries
- Implements all cryptographic primitives from scratch
- Follows Signal Protocol specifications exactly
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

* Signal Protocol team for the protocol specification
* BEAM community for NIF documentation and examples
* Contributors and maintainers of the project 