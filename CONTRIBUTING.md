# Contributing to libsignal-protocol-nif

Thank you for your interest in contributing to libsignal-protocol-nif! This document provides guidelines for contributing to the project.

## 🚀 Quick Start

### Prerequisites

- **Nix** (for development environment)
- **Git** (for version control)
- **Basic knowledge** of Erlang, Elixir, and/or Gleam

### Development Setup

1. **Clone the repository:**

   ```bash
   git clone https://github.com/hydepwns/libsignal-protocol-nif.git
   cd libsignal-protocol-nif
   ```

2. **Enter the development environment:**

   ```bash
   nix-shell
   ```

3. **Build the project:**

   ```bash
   make build
   ```

4. **Run tests:**
   ```bash
   make test-unit
   ```

## 🏗️ Project Structure

```
libsignal-protocol-nif/
├── c_src/                    # C NIF implementation
│   ├── crypto/              # Cryptographic operations
│   ├── keys/                # Key management
│   ├── session/             # Session handling
│   └── utils/               # Utility functions
├── erl_src/                 # Erlang source code
├── wrappers/                # Language wrappers
│   ├── elixir/              # Elixir wrapper
│   └── gleam/               # Gleam wrapper
├── test/                    # Test suites
│   ├── erl/                 # Erlang tests
│   ├── elixir/              # Elixir tests
│   └── gleam/               # Gleam tests
└── docs/                    # Documentation
```

## 📝 Code Style Guidelines

### C Code (NIF Implementation)

- **Formatting:** Use consistent indentation (2 spaces)
- **Naming:** Use snake_case for functions and variables
- **Comments:** Document all public functions with clear descriptions
- **Error Handling:** Always check return values and handle errors gracefully
- **Memory Management:** Use `sodium_memzero()` for sensitive data

```c
/**
 * Generate a Curve25519 key pair for ECDH key exchange.
 *
 * @param env Erlang environment
 * @param argc Number of arguments (should be 0)
 * @param argv Argument array (unused)
 * @return {ok, {PublicKey, PrivateKey}} or {error, Reason}
 */
static ERL_NIF_TERM generate_curve25519_keypair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    // Implementation here
}
```

### Erlang Code

- **Formatting:** Use `rebar3 format` for consistent formatting
- **Naming:** Use snake_case for functions and variables
- **Documentation:** Use `@doc` and `@spec` for all public functions
- **Error Handling:** Return `{ok, Result}` or `{error, Reason}`

```erlang
%% @doc Generate a Curve25519 key pair for ECDH key exchange.
%% @returns {ok, {PublicKey, PrivateKey}} or {error, Reason}
-spec generate_curve25519_keypair() -> {ok, {binary(), binary()}} | {error, term()}.
generate_curve25519_keypair() ->
    % Implementation here
    ok.
```

### Elixir Code

- **Formatting:** Use `mix format` for consistent formatting
- **Naming:** Use snake_case for functions and variables
- **Documentation:** Use `@doc` and `@spec` for all public functions
- **Error Handling:** Return `{:ok, result}` or `{:error, reason}`

```elixir
@doc """
Generate a Curve25519 key pair for ECDH key exchange.

## Returns

  * `{:ok, {public_key, private_key}}` - Successfully generated key pair
  * `{:error, reason}` - Key generation failed

## Examples

    iex> SignalProtocol.generate_curve25519_keypair()
    {:ok, {public_key, private_key}}

"""
@spec generate_curve25519_keypair() :: {:ok, {binary(), binary()}} | {:error, term()}
def generate_curve25519_keypair do
  # Implementation here
end
```

### Gleam Code

- **Formatting:** Use `gleam format` for consistent formatting
- **Naming:** Use snake_case for functions and variables
- **Documentation:** Use `///` for documentation comments
- **Error Handling:** Use `Result` types for error handling

```gleam
/// Generate a Curve25519 key pair for ECDH key exchange.
///
/// Returns `Ok(#(PublicKey, PrivateKey))` on success or `Error(String)` on failure.
pub fn generate_curve25519_keypair() -> Result(#(Binary, Binary), String) {
  // Implementation here
}
```

## 🧪 Testing Guidelines

### Running Tests

```bash
# Run all tests
make test

# Run specific test suites
make test-unit        # Unit tests only
make test-integration # Integration tests only
make test-smoke       # Smoke tests only

# Run tests with coverage
make test-cover

# Run tests for specific wrappers
cd wrappers/elixir && mix test
cd wrappers/gleam && gleam test
```

### Writing Tests

- **Coverage:** Aim for 90%+ test coverage
- **Naming:** Use descriptive test names that explain the scenario
- **Structure:** Use the Arrange-Act-Assert pattern
- **Isolation:** Each test should be independent and not affect others

#### Erlang Test Example

```erlang
generate_curve25519_keypair_test() ->
    % Arrange
    % (setup if needed)

    % Act
    {ok, {PublicKey, PrivateKey}} = signal_nif:generate_curve25519_keypair(),

    % Assert
    ?assertEqual(32, byte_size(PublicKey)),
    ?assertEqual(32, byte_size(PrivateKey)),
    ?assertNotEqual(PublicKey, PrivateKey).
```

#### Elixir Test Example

```elixir
test "generates valid Curve25519 key pair" do
  # Arrange
  # (setup if needed)

  # Act
  {:ok, {public_key, private_key}} = SignalProtocol.generate_curve25519_keypair()

  # Assert
  assert byte_size(public_key) == 32
  assert byte_size(private_key) == 32
  assert public_key != private_key
end
```

#### Gleam Test Example

```gleam
pub fn generate_curve25519_keypair_test() {
  // Arrange
  // (setup if needed)

  // Act
  let Ok(#(public_key, private_key)) = signal_protocol.generate_curve25519_keypair()

  // Assert
  assert byte_size(public_key) == 32
  assert byte_size(private_key) == 32
  assert public_key != private_key
}
```

## 🔒 Security Guidelines

### Cryptographic Code

- **Never log sensitive data** (keys, plaintext, etc.)
- **Use secure random number generation** (libsodium's `randombytes_buf`)
- **Clear sensitive memory** with `sodium_memzero()`
- **Validate all inputs** before cryptographic operations
- **Use constant-time operations** where possible

### Code Review Security Checklist

- [ ] No sensitive data in logs or error messages
- [ ] All cryptographic inputs are validated
- [ ] Memory is properly cleared after use
- [ ] No timing attacks possible
- [ ] Error messages don't leak sensitive information

## 📋 Pull Request Process

### Before Submitting

1. **Ensure tests pass:**

   ```bash
   make test
   ```

2. **Check code formatting:**

   ```bash
   rebar3 format
   mix format
   gleam format
   ```

3. **Update documentation** if adding new features

4. **Add tests** for new functionality

### Pull Request Guidelines

1. **Title:** Use clear, descriptive titles (e.g., "Add AES-GCM encryption support")

2. **Description:** Include:

   - What the change does
   - Why the change is needed
   - How to test the change
   - Any breaking changes

3. **Scope:** Keep PRs focused on a single feature or bug fix

4. **Tests:** Include tests for new functionality

### Review Process

1. **Automated checks** must pass (tests, formatting, etc.)
2. **Code review** by maintainers
3. **Security review** for cryptographic changes
4. **Documentation review** for new features

## 🚀 Release Process

### Version Numbering

We use [Semantic Versioning](https://semver.org/):

- **MAJOR.MINOR.PATCH**
- **MAJOR:** Breaking changes
- **MINOR:** New features (backward compatible)
- **PATCH:** Bug fixes (backward compatible)

### Release Checklist

- [ ] All tests pass
- [ ] Documentation is updated
- [ ] Version numbers are updated in all packages
- [ ] Changelog is updated
- [ ] Packages are published to Hex.pm

### Publishing to Hex.pm

```bash
# Publish all packages
make publish-wrappers

# Publish individual packages
cd wrappers/elixir && mix hex.publish
cd wrappers/gleam && rebar3 hex publish
rebar3 hex publish --replace
```

## 🐛 Bug Reports

### Before Reporting

1. **Check existing issues** to avoid duplicates
2. **Try the latest version** to ensure the bug still exists
3. **Reproduce the issue** with minimal code

### Bug Report Template

```markdown
**Description:**
Brief description of the issue

**Steps to Reproduce:**

1. Step 1
2. Step 2
3. Step 3

**Expected Behavior:**
What should happen

**Actual Behavior:**
What actually happens

**Environment:**

- OS: [e.g., macOS 14.0]
- Erlang/OTP: [e.g., 27.0]
- Elixir: [e.g., 1.15.0] (if applicable)
- Gleam: [e.g., 0.37.0] (if applicable)

**Additional Information:**
Any other relevant details
```

## 💡 Feature Requests

### Before Requesting

1. **Check existing issues** to avoid duplicates
2. **Consider the scope** and impact
3. **Think about implementation** approach

### Feature Request Template

```markdown
**Description:**
Brief description of the feature

**Use Case:**
Why this feature is needed

**Proposed Implementation:**
How you think it should work

**Alternatives Considered:**
Other approaches you've considered

**Additional Information:**
Any other relevant details
```

## 🤝 Community Guidelines

### Code of Conduct

- **Be respectful** and inclusive
- **Help others** learn and grow
- **Provide constructive feedback**
- **Focus on the code**, not the person

### Communication

- **Use clear language** and avoid jargon
- **Provide context** for questions and issues
- **Be patient** with newcomers
- **Celebrate contributions** and improvements

## 📞 Getting Help

- **Issues:** Use GitHub issues for bugs and feature requests
- **Discussions:** Use GitHub discussions for questions and ideas
- **Documentation:** Check the [docs/](docs/) directory for detailed guides

## 🙏 Thank You

Thank you for contributing to libsignal-protocol-nif! Your contributions help make the BEAM ecosystem more secure and powerful for everyone.
