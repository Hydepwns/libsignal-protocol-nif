-module(signal_nif).

-on_load(load_nif/0).

-export([
    % Legacy functions
    test_function/0,
    test_crypto/0,
    test_curve25519/0,
    generate_curve25519_keypair/0,
    compute_shared_secret/2,

    % Crypto functions
    aes_gcm_encrypt/5,
    aes_gcm_decrypt/6,
    hmac_sha256/2,
    sha256/1,
    sha512/1,
    generate_ed25519_keypair/0,
    sign_data/2,
    verify_signature/3,

    % Session management
    create_session/0,
    process_pre_key_bundle/2,
    encrypt_message/2,
    decrypt_message/2,

    % Protocol functions
    generate_pre_key/1,
    generate_signed_pre_key/2,

    % Cache management
    get_cache_stats/0,
    reset_cache_stats/0,
    set_cache_size/3
]).

% ============================================================================
% LEGACY FUNCTIONS
% ============================================================================

test_function() ->
    erlang:nif_error(nif_not_loaded).

test_crypto() ->
    erlang:nif_error(nif_not_loaded).

test_curve25519() ->
    erlang:nif_error(nif_not_loaded).

generate_curve25519_keypair() ->
    erlang:nif_error(nif_not_loaded).

compute_shared_secret(_PrivateKey, _PublicKey) ->
    erlang:nif_error(nif_not_loaded).

% ============================================================================
% CRYPTO FUNCTIONS
% ============================================================================

aes_gcm_encrypt(_Key, _IV, _Plaintext, _AAD, _TagLen) ->
    erlang:nif_error(nif_not_loaded).

aes_gcm_decrypt(_Key, _IV, _Ciphertext, _AAD, _Tag, _PlaintextLen) ->
    erlang:nif_error(nif_not_loaded).

hmac_sha256(_Key, _Data) ->
    erlang:nif_error(nif_not_loaded).

sha256(_Data) ->
    erlang:nif_error(nif_not_loaded).

sha512(_Data) ->
    erlang:nif_error(nif_not_loaded).

generate_ed25519_keypair() ->
    erlang:nif_error(nif_not_loaded).

sign_data(_PrivateKey, _Data) ->
    erlang:nif_error(nif_not_loaded).

verify_signature(_PublicKey, _Data, _Signature) ->
    erlang:nif_error(nif_not_loaded).

% ============================================================================
% SESSION MANAGEMENT
% ============================================================================

create_session() ->
    erlang:nif_error(nif_not_loaded).

process_pre_key_bundle(_Session, _Bundle) ->
    erlang:nif_error(nif_not_loaded).

encrypt_message(_Session, _Message) ->
    erlang:nif_error(nif_not_loaded).

decrypt_message(_Session, _EncryptedMessage) ->
    erlang:nif_error(nif_not_loaded).

% ============================================================================
% PROTOCOL FUNCTIONS
% ============================================================================

generate_pre_key(_KeyId) ->
    erlang:nif_error(nif_not_loaded).

generate_signed_pre_key(_KeyId, _IdentityKey) ->
    erlang:nif_error(nif_not_loaded).

% ============================================================================
% CACHE MANAGEMENT
% ============================================================================

get_cache_stats() ->
    erlang:nif_error(nif_not_loaded).

reset_cache_stats() ->
    erlang:nif_error(nif_not_loaded).

set_cache_size(_ChainKeySize, _RootKeySize, _MessageKeySize) ->
    erlang:nif_error(nif_not_loaded).

% ============================================================================
% NIF LOADING
% ============================================================================

load_nif() ->
    % Try multiple possible paths for the NIF library
    Paths = [
        % From erl_src
        "../priv/signal_nif",
        % From test/erl - this is the most likely path for tests
        "../../priv/signal_nif",
        % From test/erl with explicit .dylib extension (macOS)
        "../../priv/signal_nif.dylib",
        % From project root
        "priv/signal_nif",
        % From current directory
        "./priv/signal_nif",
        % Absolute path
        "/Users/droo/Documents/CODE/libsignal-protocol-nif/priv/signal_nif",
        % Absolute path with .dylib
        "/Users/droo/Documents/CODE/libsignal-protocol-nif/priv/signal_nif.dylib"
    ],

    load_nif_from_paths(Paths).

load_nif_from_paths([]) ->
    {error, "Could not load signal_nif from any path"};
load_nif_from_paths([Path | Rest]) ->
    io:format("Trying to load NIF from: ~s~n", [Path]),
    case erlang:load_nif(Path, 0) of
        ok ->
            io:format("Successfully loaded NIF from: ~s~n", [Path]),
            ok;
        {error, {load_failed, Reason}} ->
            io:format("Failed to load from ~s: ~s~n", [Path, Reason]),
            load_nif_from_paths(Rest);
        {error, Reason} ->
            io:format("Error loading from ~s: ~p~n", [Path, Reason]),
            load_nif_from_paths(Rest)
    end.
