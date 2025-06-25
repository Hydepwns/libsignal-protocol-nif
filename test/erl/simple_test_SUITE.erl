-module(simple_test_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(export_all).

all() ->
    [fast, expensive].

groups() ->
    [{fast, [], [test_basic_functionality, test_key_generation, test_session]},
     {expensive, [], [test_performance]}].

init_per_suite(Config) ->
    io:format("simple_test_SUITE: init_per_suite starting~n", []),
    application:ensure_all_started(nif),
    case nif:init() of
        ok ->
            io:format("NIF initialized successfully~n"),
            Config;
        {error, Reason} ->
            io:format("Failed to initialize NIF: ~p~n", [Reason]),
            {skip, "NIF initialization failed"}
    end.

end_per_suite(_Config) ->
    ok.

init_per_group(fast, Config) ->
    io:format("Running fast simple tests~n"),
    Config;
init_per_group(expensive, Config) ->
    io:format("Running expensive simple tests~n"),
    Config.

end_per_group(_, _Config) ->
    ok.

test_basic_functionality(_Config) ->
    % Test basic functionality that doesn't require the NIF
    ?assertEqual(2, 1 + 1),
    ?assert(is_list([1, 2, 3])),
    ?assert(is_binary(<<"test">>)),
    io:format("Basic test passed~n").

test_nif_loading(_Config) ->
    % Test if we can load the NIF
    io:format("Testing NIF loading...~n"),
    case nif:init() of
        ok ->
            io:format("NIF loaded successfully~n"),
            % Try to call a simple wrapper function
            case signal_crypto:generate_key_pair() of
                {ok, {PublicKey, PrivateKey}} ->
                    io:format("Wrapper function call successful~n"),
                    io:format("PublicKey type: ~p, value: ~p~n",
                              [erlang:is_binary(PublicKey), PublicKey]),
                    io:format("PrivateKey type: ~p, value: ~p~n",
                              [erlang:is_binary(PrivateKey), PrivateKey]),
                    ?assert(is_binary(PublicKey)),
                    ?assert(is_binary(PrivateKey));
                {error, Reason} ->
                    io:format("Wrapper function call failed: ~p~n", [Reason]),
                    ?assert(false, "Wrapper function call failed");
                Other ->
                    io:format("Wrapper function returned unexpected result: ~p~n", [Other]),
                    ?assert(false, "Wrapper function returned unexpected result")
            end;
        {error, Reason} ->
            io:format("NIF loading failed: ~p~n", [Reason]),
            ?assert(false, "NIF loading failed")
    end.

test_session(_Config) ->
    % Test session functionality
    {ok, {LocalPublic, _}} = signal_crypto:generate_key_pair(),
    {ok, {RemotePublic, _}} = signal_crypto:generate_key_pair(),
    Session = signal_session:new(LocalPublic, RemotePublic),
    ?assert(is_binary(signal_session:get_session_id(Session))),
    ?assertEqual(LocalPublic, maps:get(local_identity_key, Session)),
    ?assertEqual(RemotePublic, maps:get(remote_identity_key, Session)).
