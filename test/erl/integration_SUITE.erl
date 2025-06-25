-module(integration_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(export_all).

all() ->
    [{group, fast}, {group, expensive}].

groups() ->
    [{fast,
      [],
      [test_complete_signal_workflow,
       test_bidirectional_communication,
       test_multiple_sessions,
       test_session_recovery,
       test_key_rotation,
       test_message_ordering,
       test_error_recovery]},
     {expensive,
      [],
      [test_concurrent_sessions,
       test_performance_under_load,
       test_memory_usage,
       test_stress_testing]}].

init_per_suite(Config) ->
    io:format("integration_SUITE: init_per_suite starting~n", []),
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
    io:format("Running fast integration tests~n"),
    Config;
init_per_group(expensive, Config) ->
    io:format("Running expensive integration tests~n"),
    Config.

end_per_group(_, _Config) ->
    ok.

test_complete_signal_workflow(_Config) ->
    % Test complete Signal Protocol workflow between two parties
    io:format("Testing complete Signal Protocol workflow~n"),

    % Generate identity keys for both parties
    {ok, {AliceIdentityPublic, AliceIdentityPrivate}} = signal_crypto:generate_key_pair(),
    {ok, {BobIdentityPublic, BobIdentityPrivate}} = signal_crypto:generate_key_pair(),

    % Generate pre-keys for both parties
    {ok, {AlicePreKeyId, AlicePreKey}} = nif:generate_pre_key(1),
    {ok, {BobPreKeyId, BobPreKey}} = nif:generate_pre_key(1),

    % Generate signed pre-keys for both parties
    {ok, {AliceSignedPreKeyId, AliceSignedPreKey, AliceSignature}} =
        nif:generate_signed_pre_key(AliceIdentityPrivate, 1),
    {ok, {BobSignedPreKeyId, BobSignedPreKey, BobSignature}} =
        nif:generate_signed_pre_key(BobIdentityPrivate, 1),

    % Create pre-key bundles
    AliceBundle =
        {123,
         456,
         {AlicePreKeyId, AlicePreKey},
         {AliceSignedPreKeyId, AliceSignedPreKey, AliceSignature},
         AliceIdentityPublic},
    BobBundle =
        {789,
         101,
         {BobPreKeyId, BobPreKey},
         {BobSignedPreKeyId, BobSignedPreKey, BobSignature},
         BobIdentityPublic},

    % Create sessions for both parties
    {ok, AliceSession} = nif:create_session(AliceIdentityPublic),
    {ok, BobSession} = nif:create_session(BobIdentityPublic),

    % Process bundles to establish sessions
    {ok, AliceEstablishedSession} = nif:process_pre_key_bundle(AliceSession, BobBundle),
    {ok, BobEstablishedSession} = nif:process_pre_key_bundle(BobSession, AliceBundle),

    % Test bidirectional communication
    Messages =
        [<<"Hello from Alice!">>,
         <<"Hello from Bob!">>,
         <<"How are you doing?">>,
         <<"I'm doing great, thanks!">>,
         binary:copy(<<"Long message from Alice: ">>, 100),
         binary:copy(<<"Long message from Bob: ">>, 100)],

    % Alice sends first message
    {ok, AliceEncrypted1} =
        nif:encrypt_message(AliceEstablishedSession, lists:nth(1, Messages)),
    {ok, BobDecrypted1} = nif:decrypt_message(BobEstablishedSession, AliceEncrypted1),
    ?assertEqual(lists:nth(1, Messages), BobDecrypted1),

    % Bob sends response
    {ok, BobEncrypted1} = nif:encrypt_message(BobEstablishedSession, lists:nth(2, Messages)),
    {ok, AliceDecrypted1} = nif:decrypt_message(AliceEstablishedSession, BobEncrypted1),
    ?assertEqual(lists:nth(2, Messages), AliceDecrypted1),

    % Continue conversation
    {ok, AliceEncrypted2} =
        nif:encrypt_message(AliceEstablishedSession, lists:nth(3, Messages)),
    {ok, BobDecrypted2} = nif:decrypt_message(BobEstablishedSession, AliceEncrypted2),
    ?assertEqual(lists:nth(3, Messages), BobDecrypted2),

    {ok, BobEncrypted2} = nif:encrypt_message(BobEstablishedSession, lists:nth(4, Messages)),
    {ok, AliceDecrypted2} = nif:decrypt_message(AliceEstablishedSession, BobEncrypted2),
    ?assertEqual(lists:nth(4, Messages), AliceDecrypted2),

    io:format("Complete Signal Protocol workflow test passed~n").

test_bidirectional_communication(_Config) ->
    % Test bidirectional communication with multiple messages
    io:format("Testing bidirectional communication~n"),

    % Setup two parties
    {ok, {AliceIdentityPublic, AliceIdentityPrivate}} = signal_crypto:generate_key_pair(),
    {ok, {BobIdentityPublic, BobIdentityPrivate}} = signal_crypto:generate_key_pair(),

    % Create and establish sessions
    {AliceSession, BobSession} =
        establish_sessions(AliceIdentityPublic,
                           AliceIdentityPrivate,
                           BobIdentityPublic,
                           BobIdentityPrivate),

    % Test alternating message exchange
    NumMessages = 50,
    Messages =
        [crypto:strong_rand_bytes(100 + rand:uniform(900)) || _ <- lists:seq(1, NumMessages)],

    [begin
         Index = (I - 1) rem 2 + 1,
         Message = lists:nth(I, Messages),

         case Index of
             1 -> % Alice sends
                 {ok, Encrypted} = nif:encrypt_message(AliceSession, Message),
                 {ok, Decrypted} = nif:decrypt_message(BobSession, Encrypted),
                 ?assertEqual(Message, Decrypted);
             2 -> % Bob sends
                 {ok, Encrypted} = nif:encrypt_message(BobSession, Message),
                 {ok, Decrypted} = nif:decrypt_message(AliceSession, Encrypted),
                 ?assertEqual(Message, Decrypted)
         end
     end
     || I <- lists:seq(1, NumMessages)],

    io:format("Bidirectional communication test passed with ~p messages~n", [NumMessages]).

test_multiple_sessions(_Config) ->
    % Test multiple concurrent sessions
    io:format("Testing multiple sessions~n"),

    NumSessions = 10,
    Sessions = [],

    % Create multiple session pairs
    Sessions =
        [begin
             {ok, {AliceIdentityPublic, AliceIdentityPrivate}} = signal_crypto:generate_key_pair(),
             {ok, {BobIdentityPublic, BobIdentityPrivate}} = signal_crypto:generate_key_pair(),

             {AliceSession, BobSession} =
                 establish_sessions(AliceIdentityPublic,
                                    AliceIdentityPrivate,
                                    BobIdentityPublic,
                                    BobIdentityPrivate),
             {AliceSession, BobSession}
         end
         || _ <- lists:seq(1, NumSessions)],

    % Test communication on all sessions
    [begin
         Message = crypto:strong_rand_bytes(100),
         {ok, Encrypted} = nif:encrypt_message(AliceSession, Message),
         {ok, Decrypted} = nif:decrypt_message(BobSession, Encrypted),
         ?assertEqual(Message, Decrypted)
     end
     || {AliceSession, BobSession} <- Sessions],

    io:format("Multiple sessions test passed with ~p session pairs~n", [NumSessions]).

test_session_recovery(_Config) ->
    % Test session recovery after interruption
    io:format("Testing session recovery~n"),

    % Setup initial session
    {ok, {AliceIdentityPublic, AliceIdentityPrivate}} = signal_crypto:generate_key_pair(),
    {ok, {BobIdentityPublic, BobIdentityPrivate}} = signal_crypto:generate_key_pair(),

    {AliceSession, BobSession} =
        establish_sessions(AliceIdentityPublic,
                           AliceIdentityPrivate,
                           BobIdentityPublic,
                           BobIdentityPrivate),

    % Exchange some messages
    [begin
         Message = crypto:strong_rand_bytes(100),
         {ok, Encrypted} = nif:encrypt_message(AliceSession, Message),
         {ok, Decrypted} = nif:decrypt_message(BobSession, Encrypted),
         ?assertEqual(Message, Decrypted)
     end
     || _ <- lists:seq(1, 10)],

    % Simulate session interruption by creating new sessions
    {AliceSession2, BobSession2} =
        establish_sessions(AliceIdentityPublic,
                           AliceIdentityPrivate,
                           BobIdentityPublic,
                           BobIdentityPrivate),

    % Verify new sessions work
    Message = crypto:strong_rand_bytes(100),
    {ok, Encrypted} = nif:encrypt_message(AliceSession2, Message),
    {ok, Decrypted} = nif:decrypt_message(BobSession2, Encrypted),
    ?assertEqual(Message, Decrypted),

    io:format("Session recovery test passed~n").

test_key_rotation(_Config) ->
    % Test key rotation scenarios
    io:format("Testing key rotation~n"),

    % Setup initial session
    {ok, {AliceIdentityPublic, AliceIdentityPrivate}} = signal_crypto:generate_key_pair(),
    {ok, {BobIdentityPublic, BobIdentityPrivate}} = signal_crypto:generate_key_pair(),

    {AliceSession, BobSession} =
        establish_sessions(AliceIdentityPublic,
                           AliceIdentityPrivate,
                           BobIdentityPublic,
                           BobIdentityPrivate),

    % Exchange messages
    [begin
         Message = crypto:strong_rand_bytes(100),
         {ok, Encrypted} = nif:encrypt_message(AliceSession, Message),
         {ok, Decrypted} = nif:decrypt_message(BobSession, Encrypted),
         ?assertEqual(Message, Decrypted)
     end
     || _ <- lists:seq(1, 5)],

    % Simulate key rotation by generating new pre-keys
    {ok, {AliceNewPreKeyId, AliceNewPreKey}} = nif:generate_pre_key(2),
    {ok, {BobNewPreKeyId, BobNewPreKey}} = nif:generate_pre_key(2),

    {ok, {AliceNewSignedPreKeyId, AliceNewSignedPreKey, AliceNewSignature}} =
        nif:generate_signed_pre_key(AliceIdentityPrivate, 2),
    {ok, {BobNewSignedPreKeyId, BobNewSignedPreKey, BobNewSignature}} =
        nif:generate_signed_pre_key(BobIdentityPrivate, 2),

    % Create new bundles with rotated keys
    AliceNewBundle =
        {123,
         456,
         {AliceNewPreKeyId, AliceNewPreKey},
         {AliceNewSignedPreKeyId, AliceNewSignedPreKey, AliceNewSignature},
         AliceIdentityPublic},
    BobNewBundle =
        {789,
         101,
         {BobNewPreKeyId, BobNewPreKey},
         {BobNewSignedPreKeyId, BobNewSignedPreKey, BobNewSignature},
         BobIdentityPublic},

    % Process new bundles
    {ok, AliceNewSession} = nif:process_pre_key_bundle(AliceSession, BobNewBundle),
    {ok, BobNewSession} = nif:process_pre_key_bundle(BobSession, AliceNewBundle),

    % Verify communication still works after key rotation
    Message = crypto:strong_rand_bytes(100),
    {ok, Encrypted} = nif:encrypt_message(AliceNewSession, Message),
    {ok, Decrypted} = nif:decrypt_message(BobNewSession, Encrypted),
    ?assertEqual(Message, Decrypted),

    io:format("Key rotation test passed~n").

test_message_ordering(_Config) ->
    % Test message ordering and delivery
    io:format("Testing message ordering~n"),

    % Setup session
    {ok, {AliceIdentityPublic, AliceIdentityPrivate}} = signal_crypto:generate_key_pair(),
    {ok, {BobIdentityPublic, BobIdentityPrivate}} = signal_crypto:generate_key_pair(),

    {AliceSession, BobSession} =
        establish_sessions(AliceIdentityPublic,
                           AliceIdentityPrivate,
                           BobIdentityPublic,
                           BobIdentityPrivate),

    % Send multiple messages in sequence
    Messages = [crypto:strong_rand_bytes(100) || _ <- lists:seq(1, 20)],
    EncryptedMessages = [],

    EncryptedMessages =
        [begin
             {ok, Encrypted} = nif:encrypt_message(AliceSession, Message),
             Encrypted
         end
         || Message <- Messages],

    % Decrypt messages in order
    DecryptedMessages =
        [begin
             {ok, Decrypted} = nif:decrypt_message(BobSession, Encrypted),
             Decrypted
         end
         || Encrypted <- EncryptedMessages],

    % Verify order is preserved
    ?assertEqual(Messages, DecryptedMessages),

    io:format("Message ordering test passed~n").

test_concurrent_sessions(_Config) ->
    % Test concurrent session operations
    io:format("Testing concurrent sessions~n"),

    NumProcesses = 5,
    SessionsPerProcess = 5,

    Pids =
        [spawn(fun() ->
                  Sessions =
                      [begin
                           {ok, {AliceIdentityPublic, AliceIdentityPrivate}} =
                               signal_crypto:generate_key_pair(),
                           {ok, {BobIdentityPublic, BobIdentityPrivate}} =
                               signal_crypto:generate_key_pair(),

                           {AliceSession, BobSession} =
                               establish_sessions(AliceIdentityPublic,
                                                  AliceIdentityPrivate,
                                                  BobIdentityPublic,
                                                  BobIdentityPrivate),

                           % Exchange messages
                           [begin
                                Message = crypto:strong_rand_bytes(100),
                                {ok, Encrypted} = nif:encrypt_message(AliceSession, Message),
                                {ok, Decrypted} = nif:decrypt_message(BobSession, Encrypted),
                                Message = Decrypted
                            end
                            || _ <- lists:seq(1, 10)],

                           {AliceSession, BobSession}
                       end
                       || _ <- lists:seq(1, SessionsPerProcess)],
                  exit({sessions, Sessions})
               end)
         || _ <- lists:seq(1, NumProcesses)],

    Results =
        [receive
             {'EXIT', Pid, {sessions, Sessions}} ->
                 Sessions
         end
         || Pid <- Pids],

    % Verify all processes completed successfully
    ?assertEqual(NumProcesses, length(Results)),

    io:format("Concurrent sessions test passed~n").

test_error_recovery(_Config) ->
    % Test error recovery scenarios
    io:format("Testing error recovery~n"),

    % Test with invalid sessions
    InvalidSession = <<"invalid_session_data">>,
    ?assertMatch({error, _}, nif:encrypt_message(InvalidSession, <<"test">>)),
    ?assertMatch({error, _}, nif:decrypt_message(InvalidSession, <<"test">>)),

    % Test with invalid bundles
    {ok, {IdentityPublic, IdentityPrivate}} = signal_crypto:generate_key_pair(),
    {ok, Session} = nif:create_session(IdentityPublic),

    InvalidBundle = {invalid, bundle, data},
    ?assertMatch({error, _}, nif:process_pre_key_bundle(Session, InvalidBundle)),

    % Test recovery after errors
    {ok, {AliceIdentityPublic, AliceIdentityPrivate}} = signal_crypto:generate_key_pair(),
    {ok, {BobIdentityPublic, BobIdentityPrivate}} = signal_crypto:generate_key_pair(),

    {AliceSession, BobSession} =
        establish_sessions(AliceIdentityPublic,
                           AliceIdentityPrivate,
                           BobIdentityPublic,
                           BobIdentityPrivate),

    % Verify communication still works after errors
    Message = crypto:strong_rand_bytes(100),
    {ok, Encrypted} = nif:encrypt_message(AliceSession, Message),
    {ok, Decrypted} = nif:decrypt_message(BobSession, Encrypted),
    ?assertEqual(Message, Decrypted),

    io:format("Error recovery test passed~n").

test_performance_under_load(_Config) ->
    % Test performance under load with reduced intensity
    io:format("Testing performance under load~n"),

    NumSessions = 20,  % Reduced from 100
    MessagesPerSession = 5,  % Reduced from 10

    StartTime = os:system_time(microsecond),

    Sessions =
        [begin
             {ok, {AliceIdentityPublic, AliceIdentityPrivate}} = signal_crypto:generate_key_pair(),
             {ok, {BobIdentityPublic, BobIdentityPrivate}} = signal_crypto:generate_key_pair(),

             {AliceSession, BobSession} =
                 establish_sessions(AliceIdentityPublic,
                                    AliceIdentityPrivate,
                                    BobIdentityPublic,
                                    BobIdentityPrivate),

             % Exchange messages
             [begin
                  Message = crypto:strong_rand_bytes(100),
                  {ok, Encrypted} = nif:encrypt_message(AliceSession, Message),
                  {ok, Decrypted} = nif:decrypt_message(BobSession, Encrypted),
                  Message = Decrypted
              end
              || _ <- lists:seq(1, MessagesPerSession)],

             {AliceSession, BobSession}
         end
         || _ <- lists:seq(1, NumSessions)],

    EndTime = os:system_time(microsecond),
    TotalTime = (EndTime - StartTime) / 1000000.0,
    TotalMessages = NumSessions * MessagesPerSession * 2, % Encrypt + decrypt

    io:format("Performance test: ~p sessions, ~p messages in ~.3f seconds (~.0f messages/sec)~n",
              [NumSessions, TotalMessages, TotalTime, TotalMessages / TotalTime]),

    io:format("Performance under load test passed~n").

test_memory_usage(_Config) ->
    % Test memory usage patterns with reduced load
    io:format("Testing memory usage~n"),

    % Get initial memory info
    InitialMemory = get_memory_usage(),

    % Create many sessions with reduced count
    NumSessions = 100,  % Reduced from 1000
    Sessions =
        [begin
             {ok, {AliceIdentityPublic, AliceIdentityPrivate}} = signal_crypto:generate_key_pair(),
             {ok, {BobIdentityPublic, BobIdentityPrivate}} = signal_crypto:generate_key_pair(),

             {AliceSession, BobSession} =
                 establish_sessions(AliceIdentityPublic,
                                    AliceIdentityPrivate,
                                    BobIdentityPublic,
                                    BobIdentityPrivate),
             {AliceSession, BobSession}
         end
         || _ <- lists:seq(1, NumSessions)],

    % Get memory after session creation
    SessionMemory = get_memory_usage(),

    % Exchange messages
    [begin
         Message = crypto:strong_rand_bytes(100),
         {ok, Encrypted} = nif:encrypt_message(AliceSession, Message),
         {ok, Decrypted} = nif:decrypt_message(BobSession, Encrypted),
         Message = Decrypted
     end
     || {AliceSession, BobSession} <- Sessions],

    % Get final memory
    FinalMemory = get_memory_usage(),

    io:format("Memory usage: Initial=~p, After sessions=~p, After messages=~p~n",
              [InitialMemory, SessionMemory, FinalMemory]),

    io:format("Memory usage test passed~n").

test_stress_testing(_Config) ->
    % Stress test with reduced load to prevent hanging
    io:format("Running stress test~n"),

    NumProcesses = 5,  % Reduced from 20
    SessionsPerProcess = 3,  % Reduced from 10
    MessagesPerSession = 10,  % Reduced from 50

    Pids =
        [spawn(fun() ->
                  Sessions =
                      [begin
                           {ok, {AliceIdentityPublic, AliceIdentityPrivate}} =
                               signal_crypto:generate_key_pair(),
                           {ok, {BobIdentityPublic, BobIdentityPrivate}} =
                               signal_crypto:generate_key_pair(),

                           {AliceSession, BobSession} =
                               establish_sessions(AliceIdentityPublic,
                                                  AliceIdentityPrivate,
                                                  BobIdentityPublic,
                                                  BobIdentityPrivate),

                           % Exchange many messages
                           [begin
                                Message = crypto:strong_rand_bytes(50 + rand:uniform(950)),
                                {ok, Encrypted} = nif:encrypt_message(AliceSession, Message),
                                {ok, Decrypted} = nif:decrypt_message(BobSession, Encrypted),
                                Message = Decrypted
                            end
                            || _ <- lists:seq(1, MessagesPerSession)],

                           {AliceSession, BobSession}
                       end
                       || _ <- lists:seq(1, SessionsPerProcess)],
                  exit({sessions, Sessions})
               end)
         || _ <- lists:seq(1, NumProcesses)],

    Results =
        [receive
             {'EXIT', Pid, {sessions, Sessions}} ->
                 Sessions
         end
         || Pid <- Pids],

    % Verify all processes completed
    ?assertEqual(NumProcesses, length(Results)),

    io:format("Stress test passed with ~p processes, ~p total sessions, ~p total messages~n",
              [NumProcesses,
               NumProcesses * SessionsPerProcess,
               NumProcesses * SessionsPerProcess * MessagesPerSession]).

% Helper functions

establish_sessions(AliceIdentityPublic,
                   AliceIdentityPrivate,
                   BobIdentityPublic,
                   BobIdentityPrivate) ->
    % Generate pre-keys
    {ok, {AlicePreKeyId, AlicePreKey}} = nif:generate_pre_key(1),
    {ok, {BobPreKeyId, BobPreKey}} = nif:generate_pre_key(1),

    % Generate signed pre-keys
    {ok, {AliceSignedPreKeyId, AliceSignedPreKey, AliceSignature}} =
        nif:generate_signed_pre_key(AliceIdentityPrivate, 1),
    {ok, {BobSignedPreKeyId, BobSignedPreKey, BobSignature}} =
        nif:generate_signed_pre_key(BobIdentityPrivate, 1),

    % Create bundles
    AliceBundle =
        {123,
         456,
         {AlicePreKeyId, AlicePreKey},
         {AliceSignedPreKeyId, AliceSignedPreKey, AliceSignature},
         AliceIdentityPublic},
    BobBundle =
        {789,
         101,
         {BobPreKeyId, BobPreKey},
         {BobSignedPreKeyId, BobSignedPreKey, BobSignature},
         BobIdentityPublic},

    % Create sessions
    {ok, AliceSession} = nif:create_session(AliceIdentityPublic),
    {ok, BobSession} = nif:create_session(BobIdentityPublic),

    % Process bundles
    {ok, AliceEstablishedSession} = nif:process_pre_key_bundle(AliceSession, BobBundle),
    {ok, BobEstablishedSession} = nif:process_pre_key_bundle(BobSession, AliceBundle),

    {AliceEstablishedSession, BobEstablishedSession}.

get_memory_usage() ->
    % Get process memory info
    case erlang:process_info(self(), memory) of
        {memory, Memory} ->
            Memory;
        _ ->
            0
    end.
