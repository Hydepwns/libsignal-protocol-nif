# Immediate Actions & Quick Start

## 🚀 Get Started in 5 Minutes

### Prerequisites Check

Before starting, ensure you have the required tools:

```bash
# Check if you have the required tools
which cmake && echo "✅ CMake found" || echo "❌ CMake required"
which rebar3 && echo "✅ Rebar3 found" || echo "❌ Rebar3 required"
which nix-shell && echo "✅ Nix found" || echo "❌ Nix recommended"
```

### Quick Build & Test

```bash
# Clone and enter directory
git clone https://github.com/Hydepwns/libsignal-protocol-nif.git
cd libsignal-protocol-nif

# Build using Nix (recommended)
nix-shell --run "make build"

# Or build manually (if no Nix)
make build

# Run crypto tests to verify everything works
nix-shell --run "make test-unit"
```

### Verify Installation

```bash
# Test basic crypto operations
nix-shell --run "rebar3 ct --suite=test/erl/unit/crypto/signal_crypto_SUITE.erl"

# Expected output: All tests should pass
# ✅ Curve25519 key generation
# ✅ Ed25519 signatures
# ✅ AES-GCM encryption
# ✅ SHA-256/512 hashing
# ✅ HMAC-SHA256 authentication
```

## 🔧 Common Issues & Solutions

### Build Issues

**Problem**: `fatal error: sodium.h: No such file or directory`

```bash
# Solution: Install libsodium
# On Ubuntu/Debian:
sudo apt-get install libsodium-dev

# On macOS:
brew install libsodium

# Or use Nix (recommended):
nix-shell
```

**Problem**: `CMake Error: Could not find a package configuration file`

```bash
# Solution: Install CMake
# On Ubuntu/Debian:
sudo apt-get install cmake

# On macOS:
brew install cmake

# Or use Nix:
nix-shell
```

**Problem**: NIF loading errors

```bash
# Solution: Rebuild and copy NIFs
make clean
make build

# Verify NIF files exist
ls -la priv/*.so priv/*.dylib
```

### Runtime Issues

**Problem**: `{error, {load_failed, "Failed to load NIF library"}}`

```bash
# Solution: Check NIF paths and rebuild
make clean && make build

# For macOS users, check library paths:
otool -L priv/signal_nif.so
```

**Problem**: Test failures

```bash
# Solution: Clean and rebuild everything
make clean
make test-clean
make build
make test-unit
```

## 📋 Development Workflow

### For Contributors

1. **Setup Development Environment**

   ```bash
   # Use Nix for consistent environment
   nix-shell
   
   # Or install dependencies manually
   # See docs/CONTRIBUTING.md for details
   ```

2. **Make Changes**

   ```bash
   # Edit C code in c_src/
   # Edit Erlang code in erl_src/
   # Edit tests in test/erl/
   ```

3. **Test Your Changes**

   ```bash
   # Rebuild
   make clean && make build
   
   # Run specific test suite
   make test-unit
   
   # Run all tests
   make test
   ```

4. **Submit Changes**

   ```bash
   # Format code
   rebar3 format
   
   # Create pull request
   git add . && git commit -m "Your changes"
   git push origin your-branch
   ```

### For Package Users

1. **Add to Your Project**

   **Erlang (rebar.config)**:

   ```erlang
   {deps, [
       {libsignal_protocol_nif, "0.1.0"}
   ]}.
   ```

   **Elixir (mix.exs)**:

   ```elixir
   defp deps do
     [
       {:libsignal_protocol, "~> 0.1.0"}
     ]
   end
   ```

   **Gleam (gleam.toml)**:

   ```toml
   [dependencies]
   libsignal_protocol_gleam = "~> 0.1.0"
   ```

2. **Basic Usage Example**

   ```erlang
   % Generate key pair
   {ok, {PublicKey, PrivateKey}} = signal_nif:generate_curve25519_keypair(),
   
   % Sign data
   Message = <<"Hello, Signal Protocol!">>,
   {ok, {SignPublicKey, SignPrivateKey}} = signal_nif:generate_ed25519_keypair(),
   {ok, Signature} = signal_nif:sign_data(SignPrivateKey, Message),
   
   % Verify signature
   ok = signal_nif:verify_signature(SignPublicKey, Message, Signature).
   ```

## 🎯 Next Steps

### For New Users

1. ✅ Complete quick start above
2. 📖 Read [API Documentation](API.md)
3. 🔍 Check [Cross-Language Comparison](CROSS_LANGUAGE_COMPARISON.md)
4. 🏗️ Review [Architecture Guide](ARCHITECTURE.md)

### For Developers

1. ✅ Set up development environment
2. 📚 Read [Contributing Guide](../CONTRIBUTING.md)
3. 🔒 Review [Security Considerations](SECURITY.md)
4. 🧪 Write tests for new features

### For Production Use

1. ✅ Run full test suite
2. 🔒 Review security considerations
3. 📊 Run performance benchmarks
4. 🚀 Deploy with monitoring

## 🆘 Getting Help

- **Documentation**: Check the `docs/` directory
- **Issues**: [GitHub Issues](https://github.com/Hydepwns/libsignal-protocol-nif/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Hydepwns/libsignal-protocol-nif/discussions)
- **Security**: See [SECURITY.md](SECURITY.md) for vulnerability reporting

## 🏃‍♂️ TL;DR - Just Get It Working

```bash
# The absolute minimum to get started:
git clone https://github.com/Hydepwns/libsignal-protocol-nif.git
cd libsignal-protocol-nif
nix-shell --run "make build && make test-unit"

# If that works, you're ready to go! 🎉
```
