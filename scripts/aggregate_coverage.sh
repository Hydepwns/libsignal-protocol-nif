#!/bin/sh
set -e

echo "=== Running All Test Suites with Accumulated Coverage ==="

# Clear any existing coverage data
rm -f _build/test/cover/ct.coverdata

# Run each test suite and accumulate coverage data
echo "Running protocol_SUITE fast group..."
rebar3 as test ct --suite=test/erl/protocol_SUITE --group fast --cover

echo "Running signal_crypto_SUITE fast group..."
rebar3 as test ct --suite=test/erl/signal_crypto_SUITE --group fast --cover

echo "Running session_management_SUITE fast group..."
rebar3 as test ct --suite=test/erl/session_management_SUITE --group fast --cover

echo ""
echo "=== Combined Coverage Results ==="
rebar3 cover

echo ""
echo "=== Coverage Summary ==="
echo "Coverage data accumulated from all three test suites:"
echo "- protocol_SUITE (fast group)"
echo "- signal_crypto_SUITE (fast group)" 
echo "- session_management_SUITE (fast group)"
echo ""
echo "Coverage report available at: _build/test/cover/index.html" 