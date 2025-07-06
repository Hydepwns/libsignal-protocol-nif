#!/usr/bin/env bash

# Script to copy NIF files to all required locations
# This centralizes the NIF copying logic that was duplicated in rebar.config

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Copying NIF files from $PROJECT_ROOT/priv/ to build directories..."

# Check if priv directory exists and has NIF files
if [ ! -d "$PROJECT_ROOT/priv" ]; then
    echo "WARNING: priv directory does not exist. NIFs may not be built yet."
    exit 0
fi

# Check if any NIF files exist
nif_files_found=false
for ext in so dylib dll; do
    if ls "$PROJECT_ROOT/priv"/*.$ext 1> /dev/null 2>&1; then
        nif_files_found=true
        break
    fi
done

if [ "$nif_files_found" = false ]; then
    echo "WARNING: No NIF files found in priv directory. Building NIFs first..."
    cd "$PROJECT_ROOT/c_src"
    cmake . -DCMAKE_BUILD_TYPE=Release
    make
    cd "$PROJECT_ROOT"
    
    # Check again if build succeeded
    nif_files_found=false
    for ext in so dylib dll; do
        if ls "$PROJECT_ROOT/priv"/*.$ext 1> /dev/null 2>&1; then
            nif_files_found=true
            break
        fi
    done
    
    if [ "$nif_files_found" = false ]; then
        echo "ERROR: NIF build failed. No files created in priv directory."
        exit 1
    fi
fi

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
        cp "$PROJECT_ROOT/priv"/*.so "$PROJECT_ROOT/$target/"
        echo "Copied .so files to $target"
    fi
    
    # Copy .dylib files (macOS)
    if ls "$PROJECT_ROOT/priv"/*.dylib 1> /dev/null 2>&1; then
        cp "$PROJECT_ROOT/priv"/*.dylib "$PROJECT_ROOT/$target/"
        echo "Copied .dylib files to $target"
    fi
    
    # Copy .dll files (Windows)
    if ls "$PROJECT_ROOT/priv"/*.dll 1> /dev/null 2>&1; then
        cp "$PROJECT_ROOT/priv"/*.dll "$PROJECT_ROOT/$target/"
        echo "Copied .dll files to $target"
    fi
done

echo "NIF files copied successfully to all target directories." 