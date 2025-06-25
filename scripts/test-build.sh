#!/bin/bash

# Simple build test script
# This script tests the basic build process

set -e

echo "=== Build Test ==="

# Clean previous builds
echo "Cleaning previous builds..."
make clean || true
rm -rf _build tmp

# Create directories
echo "Creating directories..."
mkdir -p tmp/ct_logs
mkdir -p tmp/cover
mkdir -p _build/default/lib/nif/priv
mkdir -p _build/test/lib/nif/priv

# Build NIF
echo "Building NIF..."
cd c_src
mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j"$(nproc 2>/dev/null || echo 1)"
cd ../..

# Check if NIF was built
if [[ "$OSTYPE" == "darwin"* ]]; then
    if [ -f "priv/nif.dylib" ]; then
        echo "✓ NIF built successfully (macOS)"
        cp priv/nif.dylib _build/default/lib/nif/priv/
        cp priv/nif.dylib _build/test/lib/nif/priv/
    else
        echo "✗ NIF build failed (macOS)"
        exit 1
    fi
else
    if [ -f "priv/nif.so" ]; then
        echo "✓ NIF built successfully (Linux)"
        cp priv/nif.so _build/default/lib/nif/priv/
        cp priv/nif.so _build/test/lib/nif/priv/
    else
        echo "✗ NIF build failed (Linux)"
        exit 1
    fi
fi

# Test basic Erlang compilation
echo "Testing Erlang compilation..."
rebar3 compile

echo "✓ Build test completed successfully" 