-module(signal_nif).

-on_load(load_nif/0).

-export([
    test_function/0,
    test_crypto/0,
    sha256/1,
    generate_curve25519_keypair/0
]).

test_function() ->
    erlang:nif_error(nif_not_loaded).

test_crypto() ->
    erlang:nif_error(nif_not_loaded).

sha256(_Data) ->
    erlang:nif_error(nif_not_loaded).

generate_curve25519_keypair() ->
    erlang:nif_error(nif_not_loaded).

load_nif() ->
    % Try multiple possible paths for the NIF library
    Paths = [
        % From erl_src
        "../priv/signal_nif",
        % From project root
        "priv/signal_nif",
        % From current directory
        "./priv/signal_nif"
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