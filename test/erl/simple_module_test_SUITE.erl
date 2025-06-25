-module(simple_module_test_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, test_basic_functionality/1]).

all() ->
    [test_basic_functionality].

init_per_suite(Config) ->
    io:format("simple_module_test_SUITE: init_per_suite starting~n", []),
    % Print debug information
    io:format("Current working directory: ~s~n", [element(2, file:get_cwd())]),
    io:format("Code path: ~p~n", [code:get_path()]),
    
    % Check if modules exist in the expected locations
    ModulePath = "_build/default/lib/nif/ebin/signal_crypto.beam",
    case file:read_file_info(ModulePath) of
        {ok, _} ->
            io:format("signal_crypto.beam exists at: ~s~n", [ModulePath]);
        {error, FileReason} ->
            io:format("signal_crypto.beam not found at ~s: ~p~n", [ModulePath, FileReason])
    end,
    
    % Try to load the module
    case code:load_abs("_build/default/lib/nif/ebin/signal_crypto") of
        {module, signal_crypto} ->
            io:format("signal_crypto loaded successfully via load_abs~n"),
            Config;
        {error, LoadReason} ->
            io:format("Failed to load signal_crypto via load_abs: ~p~n", [LoadReason]),
            Config
    end.

end_per_suite(_Config) ->
    ok.

test_basic_functionality(_Config) ->
    % Test if the module is available
    case erlang:function_exported(signal_crypto, generate_key_pair, 0) of
        true ->
            io:format("signal_crypto:generate_key_pair/0 is exported~n"),
            % Try to call the function
            case signal_crypto:generate_key_pair() of
                {ok, {PublicKey, PrivateKey}} ->
                    io:format("generate_key_pair succeeded~n"),
                    ?assert(is_binary(PublicKey)),
                    ?assert(is_binary(PrivateKey));
                {error, undef} ->
                    io:format("generate_key_pair returned undef~n"),
                    ?assert(false, "Function returned undef");
                Other ->
                    io:format("generate_key_pair returned: ~p~n", [Other]),
                    ?assert(false, "Unexpected result")
            end;
        false ->
            io:format("signal_crypto:generate_key_pair/0 is not exported~n"),
            ?assert(false, "Function not exported")
    end. 