#!/bin/sh

# Test script to simulate Docker build process
# This helps verify our fixes work before running the actual Docker build

set -e

echo "=== Testing Docker Build Process Simulation ==="
echo "Testing the build sequence that happens in Docker..."

# Simulate Alpine environment (no bash, use sh)
echo "1. Testing copy_nifs.sh with sh (simulating Alpine)..."
sh scripts/copy_nifs.sh

echo "2. Testing basic build commands..."
# Test cmake availability
if command -v cmake >/dev/null 2>&1; then
    echo "✓ cmake is available"
else
    echo "✗ cmake is NOT available"
    exit 1
fi

# Test make availability
if command -v make >/dev/null 2>&1; then
    echo "✓ make is available"
else
    echo "✗ make is NOT available"
    exit 1
fi

# Test pkg-config and libsodium
if pkg-config --exists libsodium; then
    echo "✓ libsodium is available"
else
    echo "✗ libsodium is NOT available"
    exit 1
fi

echo "3. Testing C build process..."
cd c_src
cmake . -DCMAKE_BUILD_TYPE=Release
make
cd ..

echo "4. Verifying NIF files exist..."
if [ -f "priv/signal_nif.so" ]; then
    echo "✓ signal_nif.so created"
else
    echo "✗ signal_nif.so NOT created"
    exit 1
fi

echo "5. Testing Erlang compilation..."
rebar3 compile

echo "6. Testing unit tests..."
make test-unit

echo ""
echo "=== All Docker Build Simulation Tests Passed! ==="
echo "The Docker build should now work correctly." 