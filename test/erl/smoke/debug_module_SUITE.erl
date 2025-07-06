-module(debug_module_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, test_module_loading/1]).

all() ->
    [test_module_loading].

init_per_suite(Config) ->
    io:format("debug_module_SUITE: init_per_suite starting~n", []),
    % Check if modules are available
    io:format("Checking module availability...~n"),
    io:format("signal_crypto module: ~p~n", [code:is_loaded(signal_crypto)]),
    io:format("nif module: ~p~n", [code:is_loaded(nif)]),
    io:format("protocol module: ~p~n", [code:is_loaded(protocol)]),
    io:format("signal_session module: ~p~n", [code:is_loaded(signal_session)]),

    % Check code path
    io:format("Code path: ~p~n", [code:get_path()]),

    % Try to load modules explicitly
    case code:ensure_loaded(signal_crypto) of
        {module, signal_crypto} ->
            io:format("signal_crypto loaded successfully~n"),
            Config;
        {error, Reason} ->
            io:format("Failed to load signal_crypto: ~p~n", [Reason]),
            {skip, "signal_crypto module loading failed"}
    end.

end_per_suite(_Config) ->
    ok.

test_module_loading(_Config) ->
    % Test if we can call signal_crypto functions
    io:format("Testing signal_crypto function calls...~n"),

    % Test basic function call
    case catch signal_crypto:generate_key_pair() of
        {ok, {PublicKey, PrivateKey}} ->
            io:format("generate_key_pair succeeded: ~p, ~p~n", [PublicKey, PrivateKey]),
            ?assert(is_binary(PublicKey)),
            ?assert(is_binary(PrivateKey));
        {error, undef} ->
            io:format("generate_key_pair returned undef~n"),
            ?assert(false, "signal_crypto:generate_key_pair/0 is undefined");
        {error, Reason} ->
            io:format("generate_key_pair failed with: ~p~n", [Reason]),
            ?assert(false, "signal_crypto:generate_key_pair/0 failed");
        Other ->
            io:format("generate_key_pair returned unexpected: ~p~n", [Other]),
            ?assert(false, "signal_crypto:generate_key_pair/0 returned unexpected result")
    end.
