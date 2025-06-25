#!/bin/bash

# Test Coverage Improvements Script
# This script runs comprehensive tests to verify coverage improvements

set -e

echo "=== Signal Protocol NIF Coverage Improvement Tests ==="
echo "Date: $(date)"
echo ""

# Clean previous builds
echo "Cleaning previous builds..."
make clean

# Build the project
echo "Building project..."
make

# Run existing tests to establish baseline
echo "Running existing tests to establish baseline..."
make test

# Run coverage analysis
echo "Running coverage analysis..."
make coverage

# Run specific module tests
echo "Running protocol module tests..."
ct_run -suite protocol_SUITE -pa ebin

echo "Running signal_session module tests..."
ct_run -suite signal_session_SUITE -pa ebin

echo "Running signal_crypto module tests..."
ct_run -suite signal_crypto_SUITE -pa ebin

# Run integration tests
echo "Running integration tests..."
ct_run -suite integration_SUITE -pa ebin

# Generate final coverage report
echo "Generating final coverage report..."
make coverage

echo ""
echo "=== Coverage Improvement Summary ==="
echo "Expected improvements:"
echo "- protocol: 0% → 80%+"
echo "- signal_session: 0% → 80%+"
echo "- Overall project: 26% → 50%+"
echo ""
echo "Check the coverage report for actual results." 