#!/bin/bash

set -e

echo "=== Testing CI Fixes Locally ==="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

success() {
    echo -e "${GREEN}✓ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

error() {
    echo -e "${RED}✗ $1${NC}"
}

# Check if we're in the project root
if [ ! -f "Makefile" ] || [ ! -f "c_src/CMakeLists.txt" ]; then
    error "Must be run from project root directory"
    exit 1
fi

echo "=== Phase 1: Check Dependencies ==="

# Check for required tools
MISSING_DEPS=()

if ! command -v cmake &> /dev/null; then
    MISSING_DEPS+=("cmake")
fi

if ! command -v pkg-config &> /dev/null; then
    MISSING_DEPS+=("pkg-config")
fi

if ! command -v rebar3 &> /dev/null; then
    MISSING_DEPS+=("rebar3")
fi

if ! command -v mix &> /dev/null; then
    MISSING_DEPS+=("mix (Elixir)")
fi

if ! command -v gleam &> /dev/null; then
    MISSING_DEPS+=("gleam")
fi

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    warning "Missing dependencies: ${MISSING_DEPS[*]}"
    warning "Some tests will be skipped"
else
    success "All required dependencies found"
fi

echo "=== Phase 2: Test Core Build ==="

if command -v cmake &> /dev/null && command -v pkg-config &> /dev/null; then
    echo "Testing core build..."
    make clean
    if make build; then
        success "Core build successful"
    else
        error "Core build failed"
        exit 1
    fi
    
    echo "Testing core tests..."
    if make test-unit; then
        success "Core unit tests passed"
    else
        warning "Core unit tests failed"
    fi
else
    warning "Skipping core build tests (missing cmake/pkg-config)"
fi

echo "=== Phase 3: Test Elixir Wrapper ==="

if command -v mix &> /dev/null; then
    echo "Testing Elixir wrapper..."
    cd wrappers/elixir
    
    # Copy NIF files if available
    if [ -f "../../priv/signal_nif.so" ] || [ -f "../../priv/signal_nif.dylib" ]; then
        mkdir -p priv
        cp -f ../../priv/*.so priv/ 2>/dev/null || true
        cp -f ../../priv/*.dylib priv/ 2>/dev/null || true
        success "NIF files copied to Elixir wrapper"
    else
        warning "No NIF files found to copy"
    fi
    
    if mix deps.get; then
        success "Elixir dependencies installed"
    else
        error "Failed to install Elixir dependencies"
        cd ../..
        exit 1
    fi
    
    if mix compile; then
        success "Elixir wrapper compiled"
    else
        error "Elixir wrapper compilation failed"
        cd ../..
        exit 1
    fi
    
    # Test with graceful failure
    if mix test; then
        success "Elixir wrapper tests passed"
    else
        warning "Elixir wrapper tests failed (may be due to NIF loading)"
    fi
    
    cd ../..
else
    warning "Skipping Elixir wrapper tests (mix not found)"
fi

echo "=== Phase 4: Test Gleam Wrapper ==="

if command -v gleam &> /dev/null; then
    echo "Testing Gleam wrapper..."
    cd wrappers/gleam
    
    # Copy NIF files if available
    if [ -f "../../priv/signal_nif.so" ] || [ -f "../../priv/signal_nif.dylib" ]; then
        mkdir -p priv
        cp -f ../../priv/*.so priv/ 2>/dev/null || true
        cp -f ../../priv/*.dylib priv/ 2>/dev/null || true
        success "NIF files copied to Gleam wrapper"
    else
        warning "No NIF files found to copy"
    fi
    
    if gleam deps download; then
        success "Gleam dependencies downloaded"
    else
        error "Failed to download Gleam dependencies"
        cd ../..
        exit 1
    fi
    
    if gleam build; then
        success "Gleam wrapper built"
    else
        error "Gleam wrapper build failed"
        cd ../..
        exit 1
    fi
    
    # Test with graceful failure
    if gleam test; then
        success "Gleam wrapper tests passed"
    else
        warning "Gleam wrapper tests failed (may be due to NIF loading)"
    fi
    
    cd ../..
else
    warning "Skipping Gleam wrapper tests (gleam not found)"
fi

echo "=== Phase 5: Test Docker Build ==="

if command -v docker &> /dev/null; then
    echo "Testing Docker build..."
    
    # Test base image build
    if docker build --target base -t libsignal-test:base -f docker/Dockerfile .; then
        success "Docker base image built"
    else
        error "Docker base image build failed"
        exit 1
    fi
    
    # Test basic functionality
    if docker run --rm libsignal-test:base sh -c "which cmake && which pkg-config"; then
        success "Docker base image has required tools"
    else
        warning "Docker base image missing some tools"
    fi
    
    # Cleanup
    docker rmi libsignal-test:base 2>/dev/null || true
else
    warning "Skipping Docker tests (docker not found)"
fi

echo "=== Summary ==="
success "CI fixes testing completed!"
echo "If you see warnings above, those issues may still cause CI failures."
echo "All errors must be fixed before CI will pass."
echo ""
echo "Next steps:"
echo "1. Fix any remaining errors shown above"
echo "2. Commit and push the changes"
echo "3. Monitor the GitHub Actions workflow" 