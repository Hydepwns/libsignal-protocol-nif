#!/usr/bin/env bash

# Script to copy NIF files to all required locations
# This centralizes the NIF copying logic that was duplicated in rebar.config

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Copying NIF files from $PROJECT_ROOT/priv/ to build directories..."

# Define target directories
TARGETS=(
    "_build/default/lib/nif/priv"
    "_build/test/lib/nif/priv"
    "_build/unit+test/lib/nif/priv"
    "_build/integration+test/lib/nif/priv"
    "_build/smoke+test/lib/nif/priv"
    "_build/unit+test/extras/test/priv"
    "_build/integration+test/extras/test/priv"
    "_build/smoke+test/extras/test/priv"
)

# Create directories and copy files
for target in "${TARGETS[@]}"; do
    mkdir -p "$PROJECT_ROOT/$target"
    
    # Copy .so files (Linux)
    if ls "$PROJECT_ROOT/priv"/*.so 1> /dev/null 2>&1; then
        cp "$PROJECT_ROOT/priv"/*.so "$PROJECT_ROOT/$target/" 2>/dev/null || true
    fi
    
    # Copy .dylib files (macOS)
    if ls "$PROJECT_ROOT/priv"/*.dylib 1> /dev/null 2>&1; then
        cp "$PROJECT_ROOT/priv"/*.dylib "$PROJECT_ROOT/$target/" 2>/dev/null || true
    fi
    
    # Copy .dll files (Windows)
    if ls "$PROJECT_ROOT/priv"/*.dll 1> /dev/null 2>&1; then
        cp "$PROJECT_ROOT/priv"/*.dll "$PROJECT_ROOT/$target/" 2>/dev/null || true
    fi
done

echo "NIF files copied successfully to all target directories." 