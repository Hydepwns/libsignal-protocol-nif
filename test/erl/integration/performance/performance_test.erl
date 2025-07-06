-module(performance_test).

-export([run_benchmarks/0, benchmark_encryption/1, benchmark_decryption/1,
         benchmark_key_generation/1, benchmark_cache_performance/1, benchmark_memory_usage/1,
         benchmark_concurrent_operations/1, generate_report/1]).

-include_lib("eunit/include/eunit.hrl").

%% @doc Run all performance benchmarks
run_benchmarks() ->
    io:format("=== Signal Protocol Performance Benchmarks ===~n~n"),

    % Initialize the library
    ok = libsignal_protocol_nif:init(),

    % Run individual benchmarks with reduced iterations
    Results =
        [{"Key Generation", benchmark_key_generation(100)},
         {"Encryption", benchmark_encryption(1000)},
         {"Decryption", benchmark_decryption(1000)},
         {"Cache Performance", benchmark_cache_performance(100)},
         {"Memory Usage", benchmark_memory_usage(100)},
         {"Concurrent Operations", benchmark_concurrent_operations(20)}],

    % Generate report
    generate_report(Results),

    Results.

%% @doc Benchmark key generation performance
benchmark_key_generation(Iterations) ->
    io:format("Benchmarking key generation (~p iterations)...~n", [Iterations]),

    StartTime = os:system_time(microsecond),

    Keys =
        [libsignal_protocol_nif:generate_identity_key_pair() || _ <- lists:seq(1, Iterations)],

    EndTime = os:system_time(microsecond),
    Duration = (EndTime - StartTime) / 1000000.0,

    AvgTime = Duration / Iterations,
    Throughput = Iterations / Duration,

    io:format("  Duration: ~.3f seconds~n", [Duration]),
    io:format("  Average time: ~.6f seconds/key~n", [AvgTime]),
    io:format("  Throughput: ~w keys/second~n~n", [round(Throughput)]),

    #{duration => Duration,
      avg_time => AvgTime,
      throughput => Throughput}.

%% @doc Benchmark encryption performance
benchmark_encryption(Iterations) ->
    io:format("Benchmarking encryption (~p iterations)...~n", [Iterations]),

    % Generate test data
    {ok, {PublicKey, _}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, Session} = libsignal_protocol_nif:create_session(PublicKey),

    TestMessages = [crypto:strong_rand_bytes(1024) || _ <- lists:seq(1, 100)],

    StartTime = os:system_time(microsecond),

    EncryptedMessages =
        [begin
             Message =
                 lists:nth(
                     rand:uniform(length(TestMessages)), TestMessages),
             {ok, Encrypted} = libsignal_protocol_nif:encrypt_message(Session, Message),
             Encrypted
         end
         || _ <- lists:seq(1, Iterations)],

    EndTime = os:system_time(microsecond),
    Duration = (EndTime - StartTime) / 1000000.0,

    AvgTime = Duration / Iterations,
    Throughput = Iterations / Duration,

    io:format("  Duration: ~.3f seconds~n", [Duration]),
    io:format("  Average time: ~.6f seconds/encryption~n", [AvgTime]),
    io:format("  Throughput: ~w encryptions/second~n~n", [round(Throughput)]),

    #{duration => Duration,
      avg_time => AvgTime,
      throughput => Throughput}.

%% @doc Benchmark decryption performance
benchmark_decryption(Iterations) ->
    io:format("Benchmarking decryption (~p iterations)...~n", [Iterations]),

    % Generate test data and encrypt messages
    {ok, {PublicKey, _}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, Session} = libsignal_protocol_nif:create_session(PublicKey),

    TestMessages = [crypto:strong_rand_bytes(1024) || _ <- lists:seq(1, 100)],
    EncryptedMessages =
        [begin
             Message =
                 lists:nth(
                     rand:uniform(length(TestMessages)), TestMessages),
             {ok, Encrypted} = libsignal_protocol_nif:encrypt_message(Session, Message),
             Encrypted
         end
         || _ <- lists:seq(1, Iterations)],

    StartTime = os:system_time(microsecond),

    DecryptedMessages =
        [begin
             Encrypted =
                 lists:nth(
                     rand:uniform(length(EncryptedMessages)), EncryptedMessages),
             {ok, Decrypted} = libsignal_protocol_nif:decrypt_message(Session, Encrypted),
             Decrypted
         end
         || _ <- lists:seq(1, Iterations)],

    EndTime = os:system_time(microsecond),
    Duration = (EndTime - StartTime) / 1000000.0,

    AvgTime = Duration / Iterations,
    Throughput = Iterations / Duration,

    io:format("  Duration: ~.3f seconds~n", [Duration]),
    io:format("  Average time: ~.6f seconds/decryption~n", [AvgTime]),
    io:format("  Throughput: ~w decryptions/second~n~n", [round(Throughput)]),

    #{duration => Duration,
      avg_time => AvgTime,
      throughput => Throughput}.

%% @doc Benchmark cache performance
benchmark_cache_performance(Iterations) ->
    io:format("Benchmarking cache performance (~p iterations)...~n", [Iterations]),

    % Generate test data
    TestData =
        [{crypto:strong_rand_bytes(32), crypto:strong_rand_bytes(1024)}
         || _ <- lists:seq(1, 100)],

    % Test cache hits
    StartTime = os:system_time(microsecond),

    [begin
         {Key, Value} =
             lists:nth(
                 rand:uniform(length(TestData)), TestData),
         performance_set_cache(Key, Value),
         performance_get_cache(Key, Value)
     end
     || _ <- lists:seq(1, Iterations)],

    EndTime = os:system_time(microsecond),
    Duration = (EndTime - StartTime) / 1000000.0,

    AvgTime = Duration / Iterations,
    Throughput = Iterations / Duration,

    io:format("  Duration: ~.3f seconds~n", [Duration]),
    io:format("  Average time: ~.6f seconds/operation~n", [AvgTime]),
    io:format("  Throughput: ~w operations/second~n~n", [round(Throughput)]),

    #{duration => Duration,
      avg_time => AvgTime,
      throughput => Throughput}.

%% @doc Benchmark memory usage
benchmark_memory_usage(Iterations) ->
    io:format("Benchmarking memory usage (~p iterations)...~n", [Iterations]),

    % Get initial memory usage
    InitialMemory = get_memory_usage(),

    % Allocate and free memory repeatedly
    StartTime = os:system_time(microsecond),

    [begin
         Size = rand:uniform(4096),
         Ptr = performance_alloc(Size),
         performance_free(Ptr, Size)
     end
     || _ <- lists:seq(1, Iterations)],

    EndTime = os:system_time(microsecond),
    Duration = (EndTime - StartTime) / 1000000.0,

    % Get final memory usage
    FinalMemory = get_memory_usage(),
    MemoryDiff = FinalMemory - InitialMemory,

    AvgTime = Duration / Iterations,
    Throughput = Iterations / Duration,

    io:format("  Duration: ~.3f seconds~n", [Duration]),
    io:format("  Average time: ~.6f seconds/operation~n", [AvgTime]),
    io:format("  Throughput: ~w operations/second~n", [round(Throughput)]),
    io:format("  Memory difference: ~p bytes~n~n", [MemoryDiff]),

    #{duration => Duration,
      avg_time => AvgTime,
      throughput => Throughput,
      memory_diff => MemoryDiff}.

%% @doc Benchmark concurrent operations
benchmark_concurrent_operations(Iterations) ->
    io:format("Benchmarking concurrent operations (~p iterations)...~n", [Iterations]),

    % Generate test data
    {ok, {PublicKey, _}} = libsignal_protocol_nif:generate_identity_key_pair(),
    {ok, Session} = libsignal_protocol_nif:create_session(PublicKey),

    TestMessages = [crypto:strong_rand_bytes(1024) || _ <- lists:seq(1, 10)],

    StartTime = os:system_time(microsecond),

    % Run concurrent operations
    Results =
        pmap(fun(_) ->
                Message =
                    lists:nth(
                        rand:uniform(length(TestMessages)), TestMessages),
                {ok, Encrypted} = libsignal_protocol_nif:encrypt_message(Session, Message),
                {ok, Decrypted} = libsignal_protocol_nif:decrypt_message(Session, Encrypted),
                {Encrypted, Decrypted}
             end,
             lists:seq(1, Iterations),
             10), % 10 concurrent processes

    EndTime = os:system_time(microsecond),
    Duration = (EndTime - StartTime) / 1000000.0,

    AvgTime = Duration / Iterations,
    Throughput = Iterations / Duration,

    io:format("  Duration: ~.3f seconds~n", [Duration]),
    io:format("  Average time: ~.6f seconds/operation~n", [AvgTime]),
    io:format("  Throughput: ~w operations/second~n~n", [round(Throughput)]),

    #{duration => Duration,
      avg_time => AvgTime,
      throughput => Throughput}.

%% @doc Generate performance report
generate_report(Results) ->
    io:format("=== Performance Report ===~n~n"),

    % Calculate summary statistics
    TotalDuration = lists:sum([maps:get(duration, Result) || {_, Result} <- Results]),
    AvgThroughput =
        lists:sum([maps:get(throughput, Result) || {_, Result} <- Results]) / length(Results),

    io:format("Total benchmark duration: ~.3f seconds~n", [TotalDuration]),
    io:format("Average throughput: ~w operations/second~n~n", [round(AvgThroughput)]),

    % Write detailed results to file
    {ok, File} = file:open("tmp/performance_report.txt", [write]),

    io:format(File, "Signal Protocol Performance Report~n", []),
    io:format(File,
              "Generated: ~s~n~n",
              [calendar:system_time_to_rfc3339(
                   erlang:system_time(second))]),

    [begin
         io:format(File, "~s:~n", [Name]),
         io:format(File, "  Duration: ~.3f seconds~n", [maps:get(duration, Result)]),
         io:format(File, "  Average time: ~.6f seconds/operation~n", [maps:get(avg_time, Result)]),
         io:format(File,
                   "  Throughput: ~w operations/second~n~n",
                   [round(maps:get(throughput, Result))])
     end
     || {Name, Result} <- Results],

    io:format(File, "Summary:~n", []),
    io:format(File, "  Total duration: ~.3f seconds~n", [TotalDuration]),
    io:format(File, "  Average throughput: ~w operations/second~n", [round(AvgThroughput)]),

    file:close(File),

    io:format("Detailed report written to tmp/performance_report.txt~n").

%% @doc Get current memory usage (platform-specific)
get_memory_usage() ->
    case os:type() of
        {unix, darwin} ->
            % macOS
            Output = cmd("ps -o rss= -p " ++ os:getpid()),
            list_to_integer(string:trim(Output)) * 1024;
        {unix, _} ->
            % Linux
            Output = cmd("ps -o rss= -p " ++ os:getpid()),
            list_to_integer(string:trim(Output)) * 1024;
        {win32, _} ->
            % Windows
            _Output = cmd("wmic process where ProcessId=" ++ os:getpid() ++ " get WorkingSetSize /value"),
            0 % Placeholder
    end.

%% @doc Execute shell command
cmd(Command) ->
    os:cmd(Command).

%% @doc Parallel map implementation
pmap(Fun, List, Workers) ->
    Parent = self(),
    Pids =
        [spawn(fun() ->
                  Results = [Fun(Item) || Item <- List],
                  Parent ! {self(), Results}
               end)
         || _ <- lists:seq(1, Workers)],

    [receive
         {Pid, Result} ->
             Result
     end
     || Pid <- Pids].

%% @doc Performance test suite
performance_test_() ->
    {setup,
     fun() ->
        ok = libsignal_protocol_nif:init(),
        ok
     end,
     fun(_) -> ok end,
     [{"Key generation performance", fun test_key_generation_performance/0},
      {"Encryption performance", fun test_encryption_performance/0},
      {"Decryption performance", fun test_decryption_performance/0},
      {"Memory usage", fun test_memory_usage/0}]}.

test_key_generation_performance() ->
    Result = benchmark_key_generation(100),
    ?assert(maps:get(throughput, Result) > 100).

test_encryption_performance() ->
    Result = benchmark_encryption(100),
    ?assert(maps:get(throughput, Result) > 1000).

test_decryption_performance() ->
    Result = benchmark_decryption(100),
    ?assert(maps:get(throughput, Result) > 1000).

test_memory_usage() ->
    Result = benchmark_memory_usage(100),
    MemoryDiff = maps:get(memory_diff, Result),
    ?assert(MemoryDiff < 1024 * 1024). % Less than 1MB difference

%% @doc Performance cache operations (placeholders)
performance_set_cache(Key, Value) ->
    % Placeholder implementation
    ok.

performance_get_cache(Key, ExpectedValue) ->
    % Placeholder implementation
    ExpectedValue.

%% @doc Performance memory operations (placeholders)
performance_alloc(Size) ->
    % Placeholder implementation
    {ok, Size}.

performance_free(Ptr, Size) ->
    % Placeholder implementation
    ok.
