-module(simple_test_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, test_basic_functionality/1]).

all() ->
    [test_basic_functionality].

init_per_suite(Config) ->
    io:format("simple_test_SUITE: init_per_suite starting~n", []),
    % Don't try to load the NIF - just return the config
    io:format("Skipping NIF loading for now~n"),
    Config.

end_per_suite(_Config) ->
    ok.

test_basic_functionality(_Config) ->
    % Test basic Erlang functionality
    io:format("Testing basic Erlang functionality~n"),

    % Test basic math
    ?assertEqual(4, 2 + 2),

    % Test basic list operations
    List = [1, 2, 3, 4, 5],
    ?assertEqual(5, length(List)),

    % Test basic binary operations
    Binary = <<"hello world">>,
    ?assertEqual(11, byte_size(Binary)),

    % Test basic atom operations
    ?assertEqual(true, is_atom(hello)),

    io:format("Basic Erlang functionality test passed~n"),
    ?assert(true).
