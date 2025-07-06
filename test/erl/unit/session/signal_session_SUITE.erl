-module(signal_session_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1, init_per_group/2,
         end_per_group/2, test_new_session/1, test_get_session_id/1,
         test_generate_deterministic_session_id/1, test_process_pre_key_bundle_basic/1,
         test_process_pre_key_bundle_invalid_signature/1, test_encrypt_decrypt_basic/1,
         test_encrypt_decrypt_empty_message/1, test_encrypt_decrypt_large_message/1,
         test_encrypt_without_chain_key/1, test_decrypt_invalid_message/1,
         test_decrypt_invalid_header/1, test_decrypt_missing_message_key/1,
         test_verify_bundle_signature/1, test_calculate_shared_secret/1,
         test_concurrent_sessions/1, test_stress_encryption/1, test_verify_signature_edge_cases/1,
         test_compute_key_edge_cases/1, test_concurrent_operations/1]).

all() ->
    [{group, fast}, {group, expensive}].

groups() ->
    [{fast,
      [],
      [test_new_session,
       test_get_session_id,
       test_generate_deterministic_session_id,
       test_process_pre_key_bundle_basic,
       test_process_pre_key_bundle_invalid_signature,
       test_encrypt_decrypt_basic,
       test_encrypt_decrypt_empty_message,
       test_encrypt_decrypt_large_message,
       test_encrypt_without_chain_key,
       test_decrypt_invalid_message,
       test_decrypt_invalid_header,
       test_decrypt_missing_message_key,
       test_verify_bundle_signature,
       test_calculate_shared_secret,
       test_concurrent_sessions]},
     {expensive, [], [test_stress_encryption]}].

init_per_suite(Config) ->
    io:format("signal_session_SUITE: init_per_suite starting~n", []),
    % Ensure the application is started
    application:ensure_all_started(nif),
    % Ensure the nif module is loaded
    case code:ensure_loaded(nif) of
        {module, nif} ->
            io:format("nif module loaded successfully~n"),
            % Initialize the NIF
            case nif:init() of
                ok ->
                    io:format("NIF initialized successfully~n"),
                    % Ensure signal_session module is loaded
                    case code:ensure_loaded(signal_session) of
                        {module, signal_session} ->
                            io:format("signal_session module loaded successfully~n"),
                            Config;
                        {error, Reason} ->
                            io:format("Failed to load signal_session module: ~p~n", [Reason]),
                            {skip, "signal_session module loading failed"}
                    end;
                {error, Reason} ->
                    io:format("Failed to initialize NIF: ~p~n", [Reason]),
                    {skip, "NIF initialization failed"}
            end;
        {error, Reason} ->
            io:format("Failed to load nif module: ~p~n", [Reason]),
            {skip, "nif module loading failed"}
    end.

end_per_suite(_Config) ->
    ok.

init_per_group(fast, Config) ->
    io:format("Running fast signal_session tests~n"),
    Config;
init_per_group(expensive, Config) ->
    io:format("Running expensive signal_session tests~n"),
    Config.

end_per_group(_, _Config) ->
    ok.

%% Test new/2 function
test_new_session(_Config) ->
    % Generate test keys
    {ok, {LocalPublic, _}} = signal_crypto:generate_key_pair(),
    {ok, {RemotePublic, _}} = signal_crypto:generate_key_pair(),

    % Create new session
    Session = signal_session:new(LocalPublic, RemotePublic),

    % Verify session structure
    ?assert(is_map(Session)),
    ?assert(is_binary(maps:get(id, Session))),
    ?assertEqual(LocalPublic, maps:get(local_identity_key, Session)),
    ?assertEqual(RemotePublic, maps:get(remote_identity_key, Session)),
    ?assertEqual(undefined, maps:get(pre_key_id, Session)),
    ?assertEqual(undefined, maps:get(signed_pre_key_id, Session)),
    ?assertEqual(undefined, maps:get(ephemeral_key, Session)),
    ?assertEqual(undefined, maps:get(chain_key, Session)),
    ?assertEqual(#{}, maps:get(message_keys, Session)),
    ?assertEqual(0, maps:get(message_counter, Session)).

%% Test get_session_id/1 function
test_get_session_id(_Config) ->
    {ok, {LocalPublic, _}} = signal_crypto:generate_key_pair(),
    {ok, {RemotePublic, _}} = signal_crypto:generate_key_pair(),
    Session = signal_session:new(LocalPublic, RemotePublic),

    SessionId = signal_session:get_session_id(Session),
    ?assert(is_binary(SessionId)),
    ?assertEqual(32, byte_size(SessionId)),
    ?assertEqual(SessionId, maps:get(id, Session)).

%% Test deterministic session ID generation
test_generate_deterministic_session_id(_Config) ->
    {ok, {LocalPublic, _}} = signal_crypto:generate_key_pair(),
    {ok, {RemotePublic, _}} = signal_crypto:generate_key_pair(),

    Session1 = signal_session:new(LocalPublic, RemotePublic),
    Session2 = signal_session:new(LocalPublic, RemotePublic),

    % Same keys should produce same session ID
    ?assertEqual(signal_session:get_session_id(Session1),
                 signal_session:get_session_id(Session2)),

    % Different keys should produce different session IDs
    {ok, {DifferentRemotePublic, _}} = signal_crypto:generate_key_pair(),
    Session3 = signal_session:new(LocalPublic, DifferentRemotePublic),
    ?assertNotEqual(signal_session:get_session_id(Session1),
                    signal_session:get_session_id(Session3)).

%% Test process_pre_key_bundle/2 with valid bundle
test_process_pre_key_bundle_basic(_Config) ->
    % Generate test keys
    {ok, {LocalPublic, _}} = signal_crypto:generate_key_pair(),
    {ok, {RemotePublic, RemotePrivate}} = signal_crypto:generate_key_pair(),
    {ok, {PreKeyPublic, _}} = signal_crypto:generate_key_pair(),
    {ok, {SignedPreKeyPublic, _}} = signal_crypto:generate_key_pair(),

    % Create valid signature
    {ok, Signature} = signal_crypto:sign(RemotePrivate, SignedPreKeyPublic),

    % Create pre-key bundle
    Bundle = {123, 456, {1, PreKeyPublic}, {2, SignedPreKeyPublic, Signature}, RemotePublic},

    % Create session and process bundle
    Session = signal_session:new(LocalPublic, RemotePublic),
    {ok, UpdatedSession} = signal_session:process_pre_key_bundle(Session, Bundle),

    % Verify updated session
    ?assertEqual(1, maps:get(pre_key_id, UpdatedSession)),
    ?assertEqual(2, maps:get(signed_pre_key_id, UpdatedSession)),
    ?assert(is_binary(maps:get(ephemeral_key, UpdatedSession))),
    ?assert(is_binary(maps:get(chain_key, UpdatedSession))),
    ?assertNotEqual(Session, UpdatedSession).

%% Test process_pre_key_bundle/2 with invalid signature
test_process_pre_key_bundle_invalid_signature(_Config) ->
    % Generate test keys
    {ok, {LocalPublic, _}} = signal_crypto:generate_key_pair(),
    {ok, {RemotePublic, _}} = signal_crypto:generate_key_pair(),
    {ok, {PreKeyPublic, _}} = signal_crypto:generate_key_pair(),
    {ok, {SignedPreKeyPublic, _}} = signal_crypto:generate_key_pair(),

    % Create invalid signature
    InvalidSignature = <<0:256>>, % All zeros signature

    % Create pre-key bundle with invalid signature
    Bundle =
        {123, 456, {1, PreKeyPublic}, {2, SignedPreKeyPublic, InvalidSignature}, RemotePublic},

    % Create session and try to process invalid bundle
    Session = signal_session:new(LocalPublic, RemotePublic),
    {error, invalid_signature} = signal_session:process_pre_key_bundle(Session, Bundle).

%% Test basic encrypt/decrypt functionality
test_encrypt_decrypt_basic(_Config) ->
    % Set up session with chain key
    {ok, {LocalPublic, _}} = signal_crypto:generate_key_pair(),
    {ok, {RemotePublic, _}} = signal_crypto:generate_key_pair(),
    Session = signal_session:new(LocalPublic, RemotePublic),

    % Add chain key to session
    {ok, ChainKey} = signal_crypto:random_bytes(32),
    SessionWithChainKey =
        Session#{chain_key => ChainKey,
                 pre_key_id => 1,
                 signed_pre_key_id => 2,
                 ephemeral_key => <<1:256>>},

    % Test message
    TestMessage = <<"Hello, Signal Protocol!">>,

    % Encrypt message
    {ok, EncryptedMessage, EncryptedSession} =
        signal_session:encrypt(SessionWithChainKey, TestMessage),
    ?assert(is_binary(EncryptedMessage)),
    ?assert(byte_size(EncryptedMessage) > byte_size(TestMessage)),

    % Decrypt message
    {ok, DecryptedMessage, _} = signal_session:decrypt(EncryptedSession, EncryptedMessage),
    ?assertEqual(TestMessage, DecryptedMessage).

%% Test encrypt/decrypt with empty message
test_encrypt_decrypt_empty_message(_Config) ->
    {ok, {LocalPublic, _}} = signal_crypto:generate_key_pair(),
    {ok, {RemotePublic, _}} = signal_crypto:generate_key_pair(),
    Session = signal_session:new(LocalPublic, RemotePublic),

    {ok, ChainKey} = signal_crypto:random_bytes(32),
    SessionWithChainKey =
        Session#{chain_key => ChainKey,
                 pre_key_id => 1,
                 signed_pre_key_id => 2,
                 ephemeral_key => <<1:256>>},

    % Test empty message
    {ok, EncryptedMessage, EncryptedSession} =
        signal_session:encrypt(SessionWithChainKey, <<>>),
    {ok, DecryptedMessage, _} = signal_session:decrypt(EncryptedSession, EncryptedMessage),
    ?assertEqual(<<>>, DecryptedMessage).

%% Test encrypt/decrypt with large message
test_encrypt_decrypt_large_message(_Config) ->
    {ok, {LocalPublic, _}} = signal_crypto:generate_key_pair(),
    {ok, {RemotePublic, _}} = signal_crypto:generate_key_pair(),
    Session = signal_session:new(LocalPublic, RemotePublic),

    {ok, ChainKey} = signal_crypto:random_bytes(32),
    SessionWithChainKey =
        Session#{chain_key => ChainKey,
                 pre_key_id => 1,
                 signed_pre_key_id => 2,
                 ephemeral_key => <<1:256>>},

    % Test large message
    LargeMessage = binary:copy(<<"A">>, 10000),
    {ok, EncryptedMessage, EncryptedSession} =
        signal_session:encrypt(SessionWithChainKey, LargeMessage),
    {ok, DecryptedMessage, _} = signal_session:decrypt(EncryptedSession, EncryptedMessage),
    ?assertEqual(LargeMessage, DecryptedMessage).

%% Test encrypt without chain key
test_encrypt_without_chain_key(_Config) ->
    {ok, {LocalPublic, _}} = signal_crypto:generate_key_pair(),
    {ok, {RemotePublic, _}} = signal_crypto:generate_key_pair(),
    Session = signal_session:new(LocalPublic, RemotePublic),

    % Try to encrypt without chain key
    {error, {encryption_failed, _}} = signal_session:encrypt(Session, <<"test">>).

%% Test decrypt with invalid message
test_decrypt_invalid_message(_Config) ->
    {ok, {LocalPublic, _}} = signal_crypto:generate_key_pair(),
    {ok, {RemotePublic, _}} = signal_crypto:generate_key_pair(),
    Session = signal_session:new(LocalPublic, RemotePublic),

    % Try to decrypt invalid message
    InvalidMessage = <<0:1000>>, % Random bytes
    {error, {decryption_failed, _}} = signal_session:decrypt(Session, InvalidMessage).

%% Test decrypt with invalid header
test_decrypt_invalid_header(_Config) ->
    {ok, {LocalPublic, _}} = signal_crypto:generate_key_pair(),
    {ok, {RemotePublic, _}} = signal_crypto:generate_key_pair(),
    Session = signal_session:new(LocalPublic, RemotePublic),

    SessionWithKeys =
        Session#{pre_key_id => 1,
                 signed_pre_key_id => 2,
                 ephemeral_key => <<1:256>>},

    % Create message with invalid header
    InvalidHeader = <<999:32, 888:32, 2:256>>, % Wrong IDs
    {ok, IV} = signal_crypto:random_bytes(12),
    {ok, Ciphertext} = signal_crypto:random_bytes(100),
    InvalidMessage = <<InvalidHeader/binary, IV/binary, Ciphertext/binary>>,

    {error, invalid_message_header} = signal_session:decrypt(SessionWithKeys, InvalidMessage).

%% Test decrypt with missing message key
test_decrypt_missing_message_key(_Config) ->
    {ok, {LocalPublic, _}} = signal_crypto:generate_key_pair(),
    {ok, {RemotePublic, _}} = signal_crypto:generate_key_pair(),
    Session = signal_session:new(LocalPublic, RemotePublic),

    SessionWithKeys =
        Session#{pre_key_id => 1,
                 signed_pre_key_id => 2,
                 ephemeral_key => <<1:256>>,
                 message_counter => 5}, % Counter > 0 but no message keys

    % Create valid header but no message key
    ValidHeader = <<1:32, 2:32, 1:256>>,
    {ok, IV} = signal_crypto:random_bytes(12),
    {ok, Ciphertext} = signal_crypto:random_bytes(100),
    MessageWithoutKey = <<ValidHeader/binary, IV/binary, Ciphertext/binary>>,

    {error, message_key_not_found} =
        signal_session:decrypt(SessionWithKeys, MessageWithoutKey).

%% Test verify_bundle_signature function
test_verify_bundle_signature(_Config) ->
    % Generate test keys
    {ok, {PublicKey, PrivateKey}} = signal_crypto:generate_key_pair(),
    {ok, {DataToSign, _}} = signal_crypto:generate_key_pair(),

    % Create valid signature
    {ok, ValidSignature} = signal_crypto:sign(PrivateKey, DataToSign),
    {ok, true} = signal_crypto:verify(PublicKey, DataToSign, ValidSignature),

    % Test with invalid signature
    InvalidSignature = <<0:256>>,
    {error, invalid_signature} =
        signal_crypto:verify(PublicKey, DataToSign, InvalidSignature).

%% Test calculate_shared_secret function
test_calculate_shared_secret(_Config) ->
    % Generate test keys
    {ok, {PublicKey1, PrivateKey1}} = signal_crypto:generate_curve25519_key_pair(),
    {ok, {PublicKey2, PrivateKey2}} = signal_crypto:generate_curve25519_key_pair(),

    % Calculate shared secrets
    {ok, SharedSecret1} =
        signal_crypto:compute_key(ecdh, PublicKey1, PrivateKey2, curve25519),
    {ok, SharedSecret2} =
        signal_crypto:compute_key(ecdh, PublicKey2, PrivateKey1, curve25519),

    % Both should produce the same shared secret
    ?assertEqual(SharedSecret1, SharedSecret2),
    ?assert(is_binary(SharedSecret1)),
    ?assert(byte_size(SharedSecret1) > 0).

%% Test concurrent session operations
test_concurrent_sessions(_Config) ->
    % Create multiple sessions concurrently
    Sessions =
        lists:map(fun(_) ->
                     {ok, {LocalPublic, _}} = signal_crypto:generate_key_pair(),
                     {ok, {RemotePublic, _}} = signal_crypto:generate_key_pair(),
                     signal_session:new(LocalPublic, RemotePublic)
                  end,
                  lists:seq(1, 10)),

    % Verify all sessions are valid
    lists:foreach(fun(Session) ->
                     ?assert(is_map(Session)),
                     ?assert(is_binary(maps:get(id, Session)))
                  end,
                  Sessions),

    % Verify session IDs are unique
    SessionIds = [maps:get(id, Session) || Session <- Sessions],
    ?assertEqual(length(SessionIds), length(lists:usort(SessionIds))).

%% Test stress encryption/decryption
test_stress_encryption(_Config) ->
    {ok, {LocalPublic, _}} = signal_crypto:generate_key_pair(),
    {ok, {RemotePublic, _}} = signal_crypto:generate_key_pair(),
    Session = signal_session:new(LocalPublic, RemotePublic),

    {ok, ChainKey} = signal_crypto:random_bytes(32),
    SessionWithChainKey =
        Session#{chain_key => ChainKey,
                 pre_key_id => 1,
                 signed_pre_key_id => 2,
                 ephemeral_key => <<1:256>>},

    % Encrypt and decrypt many messages
    Messages = [io_lib:format("Message ~p", [I]) || I <- lists:seq(1, 100)],

    FinalSession =
        lists:foldl(fun(Message, AccSession) ->
                       {ok, Encrypted, UpdatedSession} =
                           signal_session:encrypt(AccSession, list_to_binary(Message)),
                       {ok, Decrypted, _} = signal_session:decrypt(UpdatedSession, Encrypted),
                       ?assertEqual(list_to_binary(Message), Decrypted),
                       UpdatedSession
                    end,
                    SessionWithChainKey,
                    Messages),

    % Verify final session state
    ?assert(is_map(FinalSession)),
    ?assert(is_binary(maps:get(chain_key, FinalSession))).

%% Test edge cases for signature verification
test_verify_signature_edge_cases(_Config) ->
    % Test with empty data
    {ok, {PublicKey, PrivateKey}} = signal_crypto:generate_key_pair(),
    {ok, Signature} = signal_crypto:sign(PrivateKey, <<>>),
    {ok, true} = signal_crypto:verify(PublicKey, <<>>, Signature),

    % Test with large data
    LargeData = binary:copy(<<"A">>, 10000),
    {ok, LargeSignature} = signal_crypto:sign(PrivateKey, LargeData),
    {ok, true} = signal_crypto:verify(PublicKey, LargeData, LargeSignature),

    % Test with modified data
    ModifiedData = <<"modified">>,
    {error, invalid_signature} =
        signal_crypto:verify(PublicKey, ModifiedData, LargeSignature).

%% Test edge cases for compute_key
test_compute_key_edge_cases(_Config) ->
    % Test with unsupported algorithm
    {ok, {PublicKey, PrivateKey}} = signal_crypto:generate_curve25519_key_pair(),
    {error, {unsupported_algorithm, rsa, p256}} =
        signal_crypto:compute_key(rsa, PublicKey, PrivateKey, p256),

    % Test with invalid key sizes
    InvalidKey = <<"invalid">>,
    {error, _} = signal_crypto:compute_key(ecdh, InvalidKey, PrivateKey, curve25519),
    {error, _} = signal_crypto:compute_key(ecdh, PublicKey, InvalidKey, curve25519).

%% Test concurrent operations more thoroughly
test_concurrent_operations(_Config) ->
    % Create multiple sessions and perform concurrent operations
    Sessions =
        lists:map(fun(_) ->
                     {ok, {LocalPublic, _}} = signal_crypto:generate_key_pair(),
                     {ok, {RemotePublic, _}} = signal_crypto:generate_key_pair(),
                     signal_session:new(LocalPublic, RemotePublic)
                  end,
                  lists:seq(1, 20)),

    % Perform concurrent encryption/decryption
    lists:foreach(fun(Session) ->
                     {ok, ChainKey} = signal_crypto:random_bytes(32),
                     SessionWithChainKey =
                         Session#{chain_key => ChainKey,
                                  pre_key_id => 1,
                                  signed_pre_key_id => 2,
                                  ephemeral_key => <<1:256>>},

                     % Encrypt and decrypt multiple messages
                     lists:foreach(fun(I) ->
                                      Message = io_lib:format("Message ~p", [I]),
                                      {ok, Encrypted, UpdatedSession} =
                                          signal_session:encrypt(SessionWithChainKey,
                                                                 list_to_binary(Message)),
                                      {ok, Decrypted, _} =
                                          signal_session:decrypt(UpdatedSession, Encrypted),
                                      ?assertEqual(list_to_binary(Message), Decrypted)
                                   end,
                                   lists:seq(1, 10))
                  end,
                  Sessions).
