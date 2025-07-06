{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    erlang
    cmake
    gcc
    gdb
    libsodium
    pkg-config
  ];
  
  shellHook = ''
    echo "Erlang NIF development environment"
    echo "Erlang version: $(erl -noshell -eval 'io:format("~s~n", [erlang:system_info(otp_release)]), halt().')"
    echo "libsodium available for Signal Protocol cryptography"
  '';
} 