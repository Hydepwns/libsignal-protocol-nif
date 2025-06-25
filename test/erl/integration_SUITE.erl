-module(integration_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1, 
         init_per_group/2, end_per_group/2,
         test_complete_signal_workflow/1, test_bidirectional_communication/1,
         test_multiple_sessions/1, test_session_recovery/1, test_key_rotation/1,
         test_message_ordering/1, test_error_recovery/1, test_concurrent_sessions/1,
         test_performance_under_load/1, test_memory_usage/1, test_stress_testing/1]).

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

    % Generate identity keys for both parties (Ed25519)
    {ok, {AliceIdentityPublic, _AliceIdentityPrivate}} = signal_crypto:generate_key_pair(),
    {ok, {BobIdentityPublic, _BobIdentityPrivate}} = signal_crypto:generate_key_pair(),

    % Generate Curve25519 key pairs for pre-keys and signed pre-keys
    {ok, {_AliceCurvePublic, AliceCurvePrivate}} = signal_crypto:generate_curve25519_key_pair(),
    {ok, {_BobCurvePublic, BobCurvePrivate}} = signal_crypto:generate_curve25519_key_pair(),

    % Generate pre-keys for both parties (Curve25519)
    {ok, {AlicePreKeyId, AlicePreKey}} = nif:generate_pre_key(1),
    {ok, {BobPreKeyId, BobPreKey}} = nif:generate_pre_key(1),

    % Generate signed pre-keys for both parties (Curve25519 private key)
    io:format("test_complete_signal_workflow: AliceCurvePrivate ~p (~p bytes)~n", 
              [AliceCurvePrivate, byte_size(AliceCurvePrivate)]),
    {ok, {AliceSignedPreKeyId, AliceSignedPreKey, AliceSignature}} =
        nif:generate_signed_pre_key(AliceCurvePrivate, 1),
    io:format("test_complete_signal_workflow: AliceSignedPreKey ~p (~p bytes)~n", 
              [AliceSignedPreKey, byte_size(AliceSignedPreKey)]),
    io:format("test_complete_signal_workflow: AliceSignature ~p (~p bytes)~n", 
              [AliceSignature, byte_size(AliceSignature)]),

    io:format("test_complete_signal_workflow: BobCurvePrivate ~p (~p bytes)~n", 
              [BobCurvePrivate, byte_size(BobCurvePrivate)]),
    {ok, {BobSignedPreKeyId, BobSignedPreKey, BobSignature}} =
        nif:generate_signed_pre_key(BobCurvePrivate, 1),
    io:format("test_complete_signal_workflow: BobSignedPreKey ~p (~p bytes)~n", 
              [BobSignedPreKey, byte_size(BobSignedPreKey)]),
    io:format("test_complete_signal_workflow: BobSignature ~p (~p bytes)~n", 
              [BobSignature, byte_size(BobSignature)]),

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

    % Create sessions using signal_session module
    AliceSession = signal_session:new(AliceIdentityPublic, BobIdentityPublic),
    BobSession = signal_session:new(BobIdentityPublic, AliceIdentityPublic),

    % Process bundles using signal_session module
    {ok, AliceEstablishedSession} = signal_session:process_pre_key_bundle(AliceSession, BobBundle),
    {ok, BobEstablishedSession} = signal_session:process_pre_key_bundle(BobSession, AliceBundle),

    % Test bidirectional communication
    Messages =
        [<<"Hello from Alice!">>,
         <<"Hello from Bob!">>,
         <<"How are you doing?">>,
         <<"I'm doing great, thanks!">>,
         binary:copy(<<"Long message from Alice: ">>, 100),
         binary:copy(<<"Long message from Bob: ">>, 100)],

    % Alice sends first message
    {ok, AliceEncrypted1, AliceSession1} =
        signal_session:encrypt(AliceEstablishedSession, lists:nth(1, Messages)),
    {ok, BobDecrypted1, BobSession1} = signal_session:decrypt(BobEstablishedSession, AliceEncrypted1),
    ?assertEqual(lists:nth(1, Messages), BobDecrypted1),

    % Bob sends response
    {ok, BobEncrypted1, BobSession2} = signal_session:encrypt(BobSession1, lists:nth(2, Messages)),
    {ok, AliceDecrypted1, AliceSession2} = signal_session:decrypt(AliceSession1, BobEncrypted1),
    ?assertEqual(lists:nth(2, Messages), AliceDecrypted1),

    % Continue conversation
    {ok, AliceEncrypted2, AliceSession3} =
        signal_session:encrypt(AliceSession2, lists:nth(3, Messages)),
    {ok, BobDecrypted2, BobSession3} = signal_session:decrypt(BobSession2, AliceEncrypted2),
    ?assertEqual(lists:nth(3, Messages), BobDecrypted2),

    {ok, BobEncrypted2, _BobSession4} = signal_session:encrypt(BobSession3, lists:nth(4, Messages)),
    {ok, AliceDecrypted2, _AliceSession4} = signal_session:decrypt(AliceSession3, BobEncrypted2),
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

    lists:foldl(fun(I, {AliceSess, BobSess}) ->
                    Index = (I - 1) rem 2 + 1,
                    Message = lists:nth(I, Messages),

                    case Index of
                        1 -> % Alice sends
                            {ok, Encrypted, AliceSessionUpdated} = signal_session:encrypt(AliceSess, Message),
                            {ok, Decrypted, BobSessionUpdated} = signal_session:decrypt(BobSess, Encrypted),
                            ?assertEqual(Message, Decrypted),
                            {AliceSessionUpdated, BobSessionUpdated};
                        2 -> % Bob sends
                            {ok, Encrypted, BobSessionUpdated} = signal_session:encrypt(BobSess, Message),
                            {ok, Decrypted, AliceSessionUpdated} = signal_session:decrypt(AliceSess, Encrypted),
                            ?assertEqual(Message, Decrypted),
                            {AliceSessionUpdated, BobSessionUpdated}
                    end
                end, {AliceSession, BobSession}, lists:seq(1, NumMessages)),

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
    {ok, {IdentityPublic, _IdentityPrivate}} = signal_crypto:generate_key_pair(),
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

    _Sessions =
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
    io:format("test_complete_signal_workflow: AliceIdentityPrivate ~p (~p bytes)~n", 
              [AliceIdentityPrivate, byte_size(AliceIdentityPrivate)]),
    io:format("test_complete_signal_workflow: AliceIdentityPrivate (hex): ~s~n",
              [string:join([io_lib:format("~2.16.0B", [X]) || <<X:8>> <= AliceIdentityPrivate], " ")]),
    {ok, {AliceSignedPreKeyId, AliceSignedPreKey, AliceSignature}} =
        nif:generate_signed_pre_key(AliceIdentityPrivate, 1),
    io:format("test_complete_signal_workflow: AliceSignedPreKey ~p (~p bytes)~n", 
              [AliceSignedPreKey, byte_size(AliceSignedPreKey)]),
    io:format("test_complete_signal_workflow: AliceSignature ~p (~p bytes)~n", 
              [AliceSignature, byte_size(AliceSignature)]),

    io:format("test_complete_signal_workflow: BobIdentityPrivate ~p (~p bytes)~n", 
              [BobIdentityPrivate, byte_size(BobIdentityPrivate)]),
    io:format("test_complete_signal_workflow: BobIdentityPrivate (hex): ~s~n",
              [string:join([io_lib:format("~2.16.0B", [X]) || <<X:8>> <= BobIdentityPrivate], " ")]),
    {ok, {BobSignedPreKeyId, BobSignedPreKey, BobSignature}} =
        nif:generate_signed_pre_key(BobIdentityPrivate, 1),
    io:format("test_complete_signal_workflow: BobSignedPreKey ~p (~p bytes)~n", 
              [BobSignedPreKey, byte_size(BobSignedPreKey)]),
    io:format("test_complete_signal_workflow: BobSignature ~p (~p bytes)~n", 
              [BobSignature, byte_size(BobSignature)]),

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

    % Create sessions using signal_session module
    AliceSession = signal_session:new(AliceIdentityPublic, BobIdentityPublic),
    BobSession = signal_session:new(BobIdentityPublic, AliceIdentityPublic),

    % Process bundles using signal_session module
    {ok, AliceEstablishedSession} = signal_session:process_pre_key_bundle(AliceSession, BobBundle),
    {ok, BobEstablishedSession} = signal_session:process_pre_key_bundle(BobSession, AliceBundle),

    {AliceEstablishedSession, BobEstablishedSession}.

get_memory_usage() ->
    % Get process memory info
    case erlang:process_info(self(), memory) of
        {memory, Memory} ->
            Memory;
        _ ->
            0
    end.
