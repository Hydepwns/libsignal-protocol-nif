-module(test_simple_nif).

-on_load(load_nif/0).

-export([hello/0]).

hello() ->
    erlang:nif_error(nif_not_loaded).

load_nif() ->
    NifPath = filename:absname("../priv/simple_nif"),
    io:format("Loading NIF from: ~s~n", [NifPath]),
    case erlang:load_nif(NifPath, 0) of
        ok ->
            io:format("NIF loaded successfully~n"),
            ok;
        {error, Reason} ->
            io:format("NIF load failed: ~p~n", [Reason]),
            {error, Reason}
    end.
