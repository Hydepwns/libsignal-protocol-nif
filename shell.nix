{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    # Core Erlang/C dependencies (these work)
    erlang
    rebar3
    cmake
    gcc
    gdb
    libsodium
    pkg-config
    
    # Optional: Add these if available in your Nix setup
    # elixir  # Comment out if causing issues
    # gleam   # Comment out if causing issues
    # docker  # Comment out if causing issues
  ];
  
  shellHook = ''
    echo "Erlang NIF development environment (Core)"
    echo "Erlang version: $(erl -noshell -eval 'io:format("~s~n", [erlang:system_info(otp_release)]), halt().')"
    echo "libsodium available for Signal Protocol cryptography"
    echo ""
    echo "Available tools:"
    echo "  - make build       # Build the NIF"
    echo "  - make test-unit   # Run unit tests"
    echo "  - rebar3 compile   # Compile Erlang"
    echo ""
    echo "Note: For Elixir/Gleam testing, install them separately or use CI"
    echo "Core Erlang/C functionality is fully available!"
  '';
} 