# Troubleshooting

## ARM64 Segmentation Fault

**Problem**: NIF loading causes segfault on ARM64 NixOS

**Root Cause**: LLVM memory allocation bug in ARM64 architecture

**Solution**: Switch to AMD64 architecture

```bash
# Check current architecture
uname -m

# If arm64/aarch64, switch to AMD64 system
# Or use x86_64 emulation if available
```

## Common Issues

### NIF Loading Failed

```
Error: NIF library not found
```

**Fix**: Ensure libsodium is installed and NIF is compiled

```bash
nix-shell --run "cd c_src && make clean && make"
```

### Build Failures

```
Error: sodium.h not found
```

**Fix**: Install libsodium development headers

```bash
nix-shell  # Should provide libsodium automatically
```

### Key Size Mismatch

```
Expected 32 bytes, got 64
```

**Fix**: Check if using correct key type (Curve25519 vs Ed25519)

## Debug Commands

```bash
# Test NIF loading
erl -noshell -eval 'libsignal_protocol_nif:init(), halt().'

# Check crypto functionality  
bash verify_foundation.sh

# Verify architecture compatibility
file c_src/libsignal_protocol_nif.so
```
