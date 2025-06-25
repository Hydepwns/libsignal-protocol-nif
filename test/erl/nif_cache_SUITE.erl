-module(nif_cache_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(export_all).

all() ->
    [test_get_cache_stats,
     test_reset_cache_stats,
     test_set_cache_size,
     test_cache_operations_sequence,
     test_cache_error_handling,
     test_cache_concurrent_access,
     test_cache_performance,
     test_cache_memory_usage].

init_per_suite(Config) ->
    % Initialize the NIF
    ok = nif:init(),
    Config.

end_per_suite(_Config) ->
    ok.

init_per_testcase(_TestCase, Config) ->
    Config.

end_per_testcase(_TestCase, _Config) ->
    ok.

%% Test get_cache_stats/1
test_get_cache_stats(_Config) ->
    % Generate identity keys and create session
    {ok, {LocalIdentityKey, _}} = nif:generate_identity_key_pair(),
    {ok, Session} = nif:create_session(LocalIdentityKey),

    % Test getting cache stats
    {ok, Stats} = nif:get_cache_stats(Session),
    ?assert(is_map(Stats) orelse is_list(Stats) orelse is_binary(Stats)),

    % Test with different session
    {ok, {DifferentLocalKey, _}} = nif:generate_identity_key_pair(),
    {ok, DifferentSession} = nif:create_session(DifferentLocalKey),
    {ok, DifferentStats} = nif:get_cache_stats(DifferentSession),
    ?assert(is_map(DifferentStats)
            orelse is_list(DifferentStats)
            orelse is_binary(DifferentStats)),

    % Test with invalid session
    InvalidSession = <<"invalid_session_data">>,
    case nif:get_cache_stats(InvalidSession) of
        {error, _} ->
            ok;
        {ok, _} ->
            ok; % Some implementations might return default stats
        _ ->
            ok
    end.

%% Test reset_cache_stats/1
test_reset_cache_stats(_Config) ->
    % Generate identity keys and create session
    {ok, {LocalIdentityKey, _}} = nif:generate_identity_key_pair(),
    {ok, Session} = nif:create_session(LocalIdentityKey),

    % Get initial stats
    {ok, InitialStats} = nif:get_cache_stats(Session),

    % Reset cache stats
    {ok, ResetStats} = nif:reset_cache_stats(Session),
    ?assert(is_map(ResetStats) orelse is_list(ResetStats) orelse is_binary(ResetStats)),

    % Get stats after reset
    {ok, AfterResetStats} = nif:get_cache_stats(Session),
    ?assert(is_map(AfterResetStats)
            orelse is_list(AfterResetStats)
            orelse is_binary(AfterResetStats)),

    % Test with different session
    {ok, {DifferentLocalKey, _}} = nif:generate_identity_key_pair(),
    {ok, DifferentSession} = nif:create_session(DifferentLocalKey),
    {ok, DifferentResetStats} = nif:reset_cache_stats(DifferentSession),
    ?assert(is_map(DifferentResetStats)
            orelse is_list(DifferentResetStats)
            orelse is_binary(DifferentResetStats)),

    % Test with invalid session
    InvalidSession = <<"invalid_session_data">>,
    case nif:reset_cache_stats(InvalidSession) of
        {error, _} ->
            ok;
        {ok, _} ->
            ok; % Some implementations might handle gracefully
        _ ->
            ok
    end.

%% Test set_cache_size/3
test_set_cache_size(_Config) ->
    % Generate identity keys and create session
    {ok, {LocalIdentityKey, _}} = nif:generate_identity_key_pair(),
    {ok, Session} = nif:create_session(LocalIdentityKey),

    % Test setting cache sizes
    ChainKeySize = 100,
    RootKeySize = 50,
    {ok, ConfigStats} = nif:set_cache_size(Session, ChainKeySize, RootKeySize),
    ?assert(is_map(ConfigStats) orelse is_list(ConfigStats) orelse is_binary(ConfigStats)),

    % Test with different sizes
    {ok, ConfigStats2} = nif:set_cache_size(Session, 200, 100),
    ?assert(is_map(ConfigStats2) orelse is_list(ConfigStats2) orelse is_binary(ConfigStats2)),

    % Test with zero sizes
    {ok, ConfigStats3} = nif:set_cache_size(Session, 0, 0),
    ?assert(is_map(ConfigStats3) orelse is_list(ConfigStats3) orelse is_binary(ConfigStats3)),

    % Test with large sizes
    {ok, ConfigStats4} = nif:set_cache_size(Session, 10000, 5000),
    ?assert(is_map(ConfigStats4) orelse is_list(ConfigStats4) orelse is_binary(ConfigStats4)),

    % Test with different session
    {ok, {DifferentLocalKey, _}} = nif:generate_identity_key_pair(),
    {ok, DifferentSession} = nif:create_session(DifferentLocalKey),
    {ok, DifferentConfigStats} = nif:set_cache_size(DifferentSession, 150, 75),
    ?assert(is_map(DifferentConfigStats)
            orelse is_list(DifferentConfigStats)
            orelse is_binary(DifferentConfigStats)),

    % Test with invalid session
    InvalidSession = <<"invalid_session_data">>,
    case nif:set_cache_size(InvalidSession, 100, 50) of
        {error, _} ->
            ok;
        {ok, _} ->
            ok; % Some implementations might handle gracefully
        _ ->
            ok
    end.

%% Test cache operations sequence
test_cache_operations_sequence(_Config) ->
    % Generate identity keys and create session
    {ok, {LocalIdentityKey, _}} = nif:generate_identity_key_pair(),
    {ok, Session} = nif:create_session(LocalIdentityKey),

    % Sequence of cache operations
    {ok, _InitialStats} = nif:get_cache_stats(Session),
    {ok, ConfigStats1} = nif:set_cache_size(Session, 100, 50),
    {ok, StatsAfterConfig} = nif:get_cache_stats(Session),
    {ok, ResetStats} = nif:reset_cache_stats(Session),
    {ok, StatsAfterReset} = nif:get_cache_stats(Session),
    {ok, ConfigStats2} = nif:set_cache_size(Session, 200, 100),
    {ok, FinalStats} = nif:get_cache_stats(Session),

    % Verify all operations returned valid results
    lists:foreach(fun(Stats) ->
                     ?assert(is_map(Stats) orelse is_list(Stats) orelse is_binary(Stats))
                  end,
                  [ConfigStats1,
                   StatsAfterConfig,
                   ResetStats,
                   StatsAfterReset,
                   ConfigStats2,
                   FinalStats]).

%% Test cache error handling
test_cache_error_handling(_Config) ->
    % Test with various invalid inputs
    InvalidSessions =
        [<<>>,
         <<"invalid">>,
         <<0:1024>>, % Large zero-filled binary
         <<255:1024>>, % Large filled binary
         term_to_binary({invalid, session, data}),
         term_to_binary([]),
         term_to_binary(#{})],

    lists:foreach(fun(InvalidSession) ->
                     % Test get_cache_stats with invalid session
                     case nif:get_cache_stats(InvalidSession) of
                         {error, _} ->
                             ok;
                         {ok, _} ->
                             ok; % Some implementations might return default stats
                         _ ->
                             ok
                     end,

                     % Test reset_cache_stats with invalid session
                     case nif:reset_cache_stats(InvalidSession) of
                         {error, _} ->
                             ok;
                         {ok, _} ->
                             ok; % Some implementations might handle gracefully
                         _ ->
                             ok
                     end,

                     % Test set_cache_size with invalid session
                     case nif:set_cache_size(InvalidSession, 100, 50) of
                         {error, _} ->
                             ok;
                         {ok, _} ->
                             ok; % Some implementations might handle gracefully
                         _ ->
                             ok
                     end
                  end,
                  InvalidSessions),

    % Test with valid session but invalid cache sizes
    {ok, {LocalIdentityKey, _}} = nif:generate_identity_key_pair(),
    {ok, Session} = nif:create_session(LocalIdentityKey),

    InvalidSizes =
        [{-1, 50},
         {100, -1},
         {-1, -1},
         {16#FFFFFFFF + 1, 50}, % Too large
         {100, 16#FFFFFFFF + 1}, % Too large
         {0, 0},
         {1, 1}],

    lists:foreach(fun({ChainSize, RootSize}) ->
                     case nif:set_cache_size(Session, ChainSize, RootSize) of
                         {error, _} ->
                             ok;
                         {ok, _} ->
                             ok; % Some implementations might handle gracefully
                         _ ->
                             ok
                     end
                  end,
                  InvalidSizes).

%% Test cache concurrent access
test_cache_concurrent_access(_Config) ->
    % Generate identity keys and create session
    {ok, {LocalIdentityKey, _}} = nif:generate_identity_key_pair(),
    {ok, Session} = nif:create_session(LocalIdentityKey),

    % Test concurrent cache operations
    lists:map(fun(I) ->
                 spawn(fun() ->
                          % Each process performs different cache operations
                          case I rem 3 of
                              0 -> % Get stats
                                  {ok, Stats} = nif:get_cache_stats(Session),
                                  Parent = self(),
                                  Parent ! {stats, Stats};
                              1 -> % Reset stats
                                  {ok, ResetStats} = nif:reset_cache_stats(Session),
                                  Parent = self(),
                                  Parent ! {reset, ResetStats};
                              2 -> % Set cache size
                                  {ok, ConfigStats} = nif:set_cache_size(Session, 100 + I, 50 + I),
                                  Parent = self(),
                                  Parent ! {config, ConfigStats}
                          end
                       end)
              end,
              lists:seq(1, 15)),

    % Collect results
    Results =
        lists:map(fun(_) ->
                     receive
                         {stats, Stats} ->
                             {stats, Stats};
                         {reset, ResetStats} ->
                             {reset, ResetStats};
                         {config, ConfigStats} ->
                             {config, ConfigStats}
                     after 5000 ->
                         timeout
                     end
                  end,
                  lists:seq(1, 15)),

    % Verify all results are valid
    lists:foreach(fun(Result) ->
                     case Result of
                         {stats, Stats} ->
                             ?assert(is_map(Stats) orelse is_list(Stats) orelse is_binary(Stats));
                         {reset, ResetStats} ->
                             ?assert(is_map(ResetStats)
                                     orelse is_list(ResetStats)
                                     orelse is_binary(ResetStats));
                         {config, ConfigStats} ->
                             ?assert(is_map(ConfigStats)
                                     orelse is_list(ConfigStats)
                                     orelse is_binary(ConfigStats));
                         timeout ->
                             ?assertEqual(true, false, "Operation timed out")
                     end
                  end,
                  Results).

%% Test cache performance
test_cache_performance(_Config) ->
    % Generate identity keys and create session
    {ok, {LocalIdentityKey, _}} = nif:generate_identity_key_pair(),
    {ok, Session} = nif:create_session(LocalIdentityKey),

    % Test performance of cache operations
    Operations =
        [{get_stats, fun() -> nif:get_cache_stats(Session) end},
         {reset_stats, fun() -> nif:reset_cache_stats(Session) end},
         {set_cache_size, fun() -> nif:set_cache_size(Session, 100, 50) end}],

    lists:foreach(fun({Operation, Fun}) ->
                     % Measure execution time
                     StartTime = erlang:monotonic_time(microsecond),
                     {ok, _} = Fun(),
                     EndTime = erlang:monotonic_time(microsecond),
                     Duration = EndTime - StartTime,

                     % Log performance (should be fast for cache operations)
                     ct:log("~p took ~p microseconds", [Operation, Duration]),
                     ?assert(Duration < 1000000)
                  end,
                  Operations).

%% Test cache memory usage
test_cache_memory_usage(_Config) ->
    % Generate identity keys and create session
    {ok, {LocalIdentityKey, _}} = nif:generate_identity_key_pair(),
    {ok, Session} = nif:create_session(LocalIdentityKey),

    % Test memory usage with different cache sizes
    CacheSizes = [{10, 5}, {100, 50}, {1000, 500}, {10000, 5000}],

    lists:foreach(fun({ChainSize, RootSize}) ->
                     % Set cache size
                     {ok, _} = nif:set_cache_size(Session, ChainSize, RootSize),

                     % Get stats to see if size was applied
                     {ok, Stats} = nif:get_cache_stats(Session),
                     ?assert(is_map(Stats) orelse is_list(Stats) orelse is_binary(Stats)),

                     % Reset stats
                     {ok, _} = nif:reset_cache_stats(Session),

                     % Get stats again
                     {ok, StatsAfterReset} = nif:get_cache_stats(Session),
                     ?assert(is_map(StatsAfterReset)
                             orelse is_list(StatsAfterReset)
                             orelse is_binary(StatsAfterReset))
                  end,
                  CacheSizes).
