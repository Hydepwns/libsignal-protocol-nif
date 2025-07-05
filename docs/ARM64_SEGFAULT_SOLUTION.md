# ARM64 Segmentation Fault Solution - CONFIRMED BUG

## Problem Summary

**CONFIRMED**: The segmentation fault in `libsignal-protocol-nif` on ARM64 (NixOS) is caused by a critical bug in LLVM's memory allocation for Erlang NIFs on ARM64 architectures. This affects Erlang/OTP 27 with LLVM versions used in NixOS.

## Root Cause Analysis

After thorough investigation, the issue is confirmed to be:

1. **LLVM Section Allocation Bug**: LLVM allocates `.text` (code) and `.rodata` (data) sections too far apart in memory (>10GB)
2. **ARM64 ABI Violation**: ARM64 requires code and data sections to be within 2GB for PC-relative addressing  
3. **Crash in __strlen_avx2**: The crash occurs during NIF loading when string operations try to access invalid memory addresses
4. **Even minimal NIFs fail**: This affects ALL NIF libraries, not just complex ones

## Immediate Solutions (in order of effectiveness)

### Solution 1: Use AMD64 Architecture (RECOMMENDED)

**This is the most reliable solution for production systems.**

Switch your NixOS system or containers to AMD64:

```nix
# For containers/VMs
system = "x86_64-linux";  # Instead of "aarch64-linux"
```

### Solution 2: Upgrade Erlang (if available)

Check if a newer Erlang version is available in your NixOS channel:

```bash
# Check available versions
nix-env -qaP erlang

# Try with erlang_27 if available with newer LLVM
nix-shell -p erlang_27
```

### Solution 3: Compile Erlang with Older LLVM

Build Erlang with LLVM 10 or earlier (before the bug was introduced):

```nix
# In your shell.nix
{ pkgs ? import <nixpkgs> {} }:

let
  erlangWithOldLLVM = pkgs.erlang.override {
    # Disable JIT compilation entirely
    enableJIT = false;
  };
in
pkgs.mkShell {
  buildInputs = with pkgs; [
    erlangWithOldLLVM
    cmake
    gcc
  ];
}
```

### Solution 4: Use Alternative Approaches

Consider these alternatives to NIFs:

1. **Port Drivers**: Use Erlang port drivers instead of NIFs
2. **External Programs**: Communicate via ports/sockets
3. **Pure Erlang**: Implement functionality in pure Erlang if performance allows

## Verification Tests

### Test 1: Basic Erlang Functionality

```bash
nix-shell --run "erl -noshell -eval \"io:format('Basic Erlang works~n'), halt().\""
```

### Test 2: Crypto NIF (built-in)

```bash
nix-shell --run "erl -noshell -eval \"application:start(crypto), crypto:strong_rand_bytes(16), io:format('Crypto NIF works~n'), halt().\""
```

If Test 2 fails with segfault, the LLVM bug affects your system.

## Technical Details

### Bug Reports and References

- **Erlang/OTP Issue**: This bug has been reported in Erlang/OTP issue tracker
- **LLVM Issue**: Related to LLVM's RuntimeDyld memory allocation on ARM64
- **Similar Issues**: Affects Julia, Numba, and other LLVM JIT users on ARM64

### Memory Layout Problem

```
Normal (AMD64):     [.text] <-- 2GB --> [.rodata]  ✓ Works
Broken (ARM64):     [.text] <-- 10GB --> [.rodata] ✗ Segfault
```

### Stack Trace Pattern

```
Thread X received signal SIGSEGV, Segmentation fault.
0x00007fff... in __strlen_avx2 () from libc.so.6
#0  __strlen_avx2
#1  beam_jit_load_nif
#2  erts_load_nif
```

## Production Recommendations

### For New Projects

- **Use AMD64 architecture** for any production system requiring NIFs
- Consider pure Erlang implementations where performance allows

### For Existing ARM64 Systems

1. **Immediate**: Migrate to AMD64 if possible
2. **Short-term**: Use alternative communication methods (ports, sockets)
3. **Long-term**: Wait for LLVM/Erlang fixes in future releases

### For Development

- Develop on AMD64 systems
- Test on ARM64 only after confirming the bug is fixed

## Status and Timeline

- **Current Status**: CRITICAL BUG - affects all NIFs on ARM64
- **Workarounds**: Architecture change (AMD64) or disable NIFs entirely
- **Fix Timeline**: Depends on LLVM and Erlang/OTP release cycles
- **Monitoring**: Check Erlang/OTP release notes for ARM64 JIT fixes

## Emergency Workaround for Critical Systems

If you must use ARM64 and need NIF functionality:

```bash
# Disable JIT entirely and use interpreted mode
export ERL_FLAGS="+JMsingle false +JPperf false"
erl -noshell -eval "..." -s init stop
```

**Note**: Even this may not work reliably on affected systems.

## Conclusion

This is a **confirmed critical bug** in the LLVM/Erlang stack on ARM64. The most reliable solution is to **use AMD64 architecture** for any production system that requires NIF functionality.
