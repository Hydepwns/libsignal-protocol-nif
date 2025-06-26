-module(working_nif).

-on_load(load_nif/0).

-export([
    test_function/0,
    test_crypto/0,
    test_curve25519/0,
    generate_curve25519_keypair/0,
    compute_shared_secret/2
]).

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

load_nif() ->
    erlang:load_nif("../priv/nif", 0).
