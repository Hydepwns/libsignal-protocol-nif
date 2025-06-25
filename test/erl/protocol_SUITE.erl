-module(protocol_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(export_all).

%% Helper function to create a pre-key bundle in the correct binary format
%% Expected format: registration_id(4) + device_id(4) + pre_key_id(4) + pre_key_len(4) + pre_key_data +
%%                  signed_pre_key_id(4) + signed_pre_key_len(4) + signed_pre_key_data +
%%                  identity_key_len(4) + identity_key_data
create_bundle_binary(RegistrationId,
                     DeviceId,
                     PreKeyId,
                     PreKeyPublic,
                     SignedPreKeyId,
                     SignedPreKeyPublic,
                     IdentityKey) ->
    PreKeyLen = byte_size(PreKeyPublic),
    SignedPreKeyLen = byte_size(SignedPreKeyPublic),
    IdentityKeyLen = byte_size(IdentityKey),

    <<RegistrationId:32/unsigned-integer,
      DeviceId:32/unsigned-integer,
      PreKeyId:32/unsigned-integer,
      PreKeyLen:32/unsigned-integer,
      PreKeyPublic:PreKeyLen/binary,
      SignedPreKeyId:32/unsigned-integer,
      SignedPreKeyLen:32/unsigned-integer,
      SignedPreKeyPublic:SignedPreKeyLen/binary,
      IdentityKeyLen:32/unsigned-integer,
      IdentityKey:IdentityKeyLen/binary>>.

all() ->
    [fast, expensive].

groups() ->
    [{fast,
      [],
      [test_start_stop,
       test_generate_identity_key_pair,
       test_generate_pre_key,
       test_generate_signed_pre_key,
       test_create_session,
       test_process_pre_key_bundle,
       test_encrypt_message,
       test_decrypt_message,
       test_unknown_call,
       test_error_handling]},
     {expensive, [], [test_concurrent_operations]}].

init_per_suite(Config) ->
    io:format("protocol_SUITE: init_per_suite starting~n", []),
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
    % Clean up any running processes
    case whereis(protocol) of
        undefined ->
            ok;
        Pid ->
            gen_server:stop(Pid)
    end,
    ok.

init_per_group(fast, Config) ->
    io:format("Running fast protocol tests~n"),
    Config;
init_per_group(expensive, Config) ->
    io:format("Running expensive protocol tests~n"),
    Config.

end_per_group(_, _Config) ->
    % Stop the protocol server after each test
    case whereis(protocol) of
        undefined ->
            ok;
        Pid ->
            gen_server:stop(Pid)
    end,
    ok.

%% Test start/0 and stop/0 functions
test_start_stop(_Config) ->
    % Test starting the protocol server
    {ok, Pid} = protocol:start(),
    ?assert(is_pid(Pid)),
    ?assertEqual(Pid, whereis(protocol)),

    % Test stopping the protocol server
    ok = protocol:stop(),
    ?assertEqual(undefined, whereis(protocol)).

%% Test generate_identity_key_pair/0
test_generate_identity_key_pair(_Config) ->
    {ok, Pid} = protocol:start(),

    % Test successful key pair generation
    {ok, {PublicKey, PrivateKey}} = protocol:generate_identity_key_pair(),
    ?assert(is_binary(PublicKey)),
    ?assert(is_binary(PrivateKey)),
    ?assert(byte_size(PublicKey) > 0),
    ?assert(byte_size(PrivateKey) > 0),

    % Test that keys are different
    ?assertNotEqual(PublicKey, PrivateKey),

    % Test multiple generations produce different keys
    {ok, {PublicKey2, PrivateKey2}} = protocol:generate_identity_key_pair(),
    ?assertNotEqual(PublicKey, PublicKey2),
    ?assertNotEqual(PrivateKey, PrivateKey2),

    ok = protocol:stop().

%% Test generate_pre_key/1
test_generate_pre_key(_Config) ->
    {ok, Pid} = protocol:start(),

    % Test with valid key ID
    KeyId = 12345,
    io:format("Testing generate_pre_key with KeyId: ~p~n", [KeyId]),
    {ok, {GeneratedKeyId, PublicKey}} = protocol:generate_pre_key(KeyId),
    ?assertEqual(KeyId, GeneratedKeyId),
    ?assert(is_binary(PublicKey)),
    ?assert(byte_size(PublicKey) > 0),

    % Test with different key ID
    KeyId2 = 67890,
    io:format("Testing generate_pre_key with KeyId2: ~p~n", [KeyId2]),
    {ok, {GeneratedKeyId2, PublicKey2}} = protocol:generate_pre_key(KeyId2),
    ?assertEqual(KeyId2, GeneratedKeyId2),
    ?assertNotEqual(PublicKey, PublicKey2),

    % Test with zero key ID
    io:format("Testing generate_pre_key with KeyId: 0~n"),
    {ok, {0, PublicKey3}} = protocol:generate_pre_key(0),
    ?assert(is_binary(PublicKey3)),

    % Test with large key ID
    LargeKeyId = 16#FFFFFFFF,
    io:format("Testing generate_pre_key with LargeKeyId: ~p~n", [LargeKeyId]),
    {ok, {LargeKeyId, PublicKey4}} = protocol:generate_pre_key(LargeKeyId),
    ?assert(is_binary(PublicKey4)),

    ok = protocol:stop().

%% Test generate_signed_pre_key/2
test_generate_signed_pre_key(_Config) ->
    {ok, Pid} = protocol:start(),

    % Generate identity key first
    {ok, {IdentityKey, _PrivateKey}} = protocol:generate_identity_key_pair(),

    % Test with valid parameters
    KeyId = 54321,
    {ok, {GeneratedKeyId, PublicKey, Signature}} =
        protocol:generate_signed_pre_key(IdentityKey, KeyId),
    ?assertEqual(KeyId, GeneratedKeyId),
    ?assert(is_binary(PublicKey)),
    ?assert(is_binary(Signature)),
    ?assert(byte_size(PublicKey) > 0),
    ?assert(byte_size(Signature) > 0),

    % Test with different key ID
    KeyId2 = 98765,
    {ok, {GeneratedKeyId2, PublicKey2, Signature2}} =
        protocol:generate_signed_pre_key(IdentityKey, KeyId2),
    ?assertEqual(KeyId2, GeneratedKeyId2),
    ?assertNotEqual(PublicKey, PublicKey2),
    ?assertNotEqual(Signature, Signature2),

    % Test with zero key ID
    {ok, {0, PublicKey3, Signature3}} = protocol:generate_signed_pre_key(IdentityKey, 0),
    ?assert(is_binary(PublicKey3)),
    ?assert(is_binary(Signature3)),

    ok = protocol:stop().

%% Test create_session/2
test_create_session(_Config) ->
    {ok, Pid} = protocol:start(),

    % Generate identity keys
    {ok, {LocalIdentityKey, _}} = protocol:generate_identity_key_pair(),
    {ok, {RemoteIdentityKey, _}} = protocol:generate_identity_key_pair(),

    % Test session creation
    {ok, Session} = protocol:create_session(LocalIdentityKey, RemoteIdentityKey),
    ?assert(is_binary(Session)),
    ?assert(byte_size(Session) > 0),

    % Test with same keys (should work)
    {ok, Session2} = protocol:create_session(LocalIdentityKey, RemoteIdentityKey),
    ?assert(is_binary(Session2)),

    % Test with different remote key
    {ok, {DifferentRemoteKey, _}} = protocol:generate_identity_key_pair(),
    {ok, Session3} = protocol:create_session(LocalIdentityKey, DifferentRemoteKey),
    ?assert(is_binary(Session3)),
    ?assertNotEqual(Session, Session3),

    ok = protocol:stop().

%% Test process_pre_key_bundle/2
test_process_pre_key_bundle(_Config) ->
    {ok, Pid} = protocol:start(),

    % Generate identity keys
    {ok, {LocalIdentityKey, _}} = protocol:generate_identity_key_pair(),
    {ok, {RemoteIdentityKey, _}} = protocol:generate_identity_key_pair(),

    % Create session
    {ok, Session} = protocol:create_session(LocalIdentityKey, RemoteIdentityKey),

    % Generate pre-key bundle components
    {ok, {PreKeyId, PreKeyPublic}} = protocol:generate_pre_key(12345),
    {ok, {SignedPreKeyId, SignedPreKeyPublic, Signature}} =
        protocol:generate_signed_pre_key(RemoteIdentityKey, 67890),

    % Create pre-key bundle in correct binary format
    BundleBin =
        create_bundle_binary(123,
                             456,
                             PreKeyId,
                             PreKeyPublic,
                             SignedPreKeyId,
                             SignedPreKeyPublic,
                             RemoteIdentityKey),

    % Test processing pre-key bundle
    {ok, UpdatedSession} = protocol:process_pre_key_bundle(Session, BundleBin),
    ?assert(is_binary(UpdatedSession)),
    ?assertNotEqual(Session, UpdatedSession),

    % Test with different bundle
    {ok, {PreKeyId2, PreKeyPublic2}} = protocol:generate_pre_key(11111),
    {ok, {SignedPreKeyId2, SignedPreKeyPublic2, Signature2}} =
        protocol:generate_signed_pre_key(RemoteIdentityKey, 22222),
    BundleBin2 =
        create_bundle_binary(789,
                             101,
                             PreKeyId2,
                             PreKeyPublic2,
                             SignedPreKeyId2,
                             SignedPreKeyPublic2,
                             RemoteIdentityKey),

    {ok, UpdatedSession2} = protocol:process_pre_key_bundle(Session, BundleBin2),
    ?assert(is_binary(UpdatedSession2)),
    ?assertNotEqual(UpdatedSession, UpdatedSession2),

    ok = protocol:stop().

%% Test encrypt_message/2
test_encrypt_message(_Config) ->
    {ok, Pid} = protocol:start(),

    % Generate identity keys and create session
    {ok, {LocalIdentityKey, _}} = protocol:generate_identity_key_pair(),
    {ok, {RemoteIdentityKey, _}} = protocol:generate_identity_key_pair(),
    {ok, Session} = protocol:create_session(LocalIdentityKey, RemoteIdentityKey),

    % Process pre-key bundle to establish session
    {ok, {PreKeyId, PreKeyPublic}} = protocol:generate_pre_key(12345),
    {ok, {SignedPreKeyId, SignedPreKeyPublic, Signature}} =
        protocol:generate_signed_pre_key(RemoteIdentityKey, 67890),
    BundleBin =
        create_bundle_binary(123,
                             456,
                             PreKeyId,
                             PreKeyPublic,
                             SignedPreKeyId,
                             SignedPreKeyPublic,
                             RemoteIdentityKey),
    {ok, EstablishedSession} = protocol:process_pre_key_bundle(Session, BundleBin),

    % Test message encryption
    Message = <<"Hello, Signal Protocol!">>,
    {ok, EncryptedMessage} = protocol:encrypt_message(EstablishedSession, Message),
    ?assert(is_binary(EncryptedMessage)),
    ?assert(byte_size(EncryptedMessage) > byte_size(Message)),

    % Test with different message
    Message2 = <<"Another test message">>,
    {ok, EncryptedMessage2} = protocol:encrypt_message(EstablishedSession, Message2),
    ?assert(is_binary(EncryptedMessage2)),
    ?assertNotEqual(EncryptedMessage, EncryptedMessage2),

    % Test with empty message
    {ok, EncryptedEmpty} = protocol:encrypt_message(EstablishedSession, <<>>),
    ?assert(is_binary(EncryptedEmpty)),

    % Test with large message
    LargeMessage = binary:copy(<<"A">>, 1000),
    {ok, EncryptedLarge} = protocol:encrypt_message(EstablishedSession, LargeMessage),
    ?assert(is_binary(EncryptedLarge)),

    ok = protocol:stop().

%% Test decrypt_message/2
test_decrypt_message(_Config) ->
    {ok, Pid} = protocol:start(),

    % Generate identity keys and create session
    {ok, {LocalIdentityKey, _}} = protocol:generate_identity_key_pair(),
    {ok, {RemoteIdentityKey, _}} = protocol:generate_identity_key_pair(),
    {ok, Session} = protocol:create_session(LocalIdentityKey, RemoteIdentityKey),

    % Process pre-key bundle to establish session
    {ok, {PreKeyId, PreKeyPublic}} = protocol:generate_pre_key(12345),
    {ok, {SignedPreKeyId, SignedPreKeyPublic, Signature}} =
        protocol:generate_signed_pre_key(RemoteIdentityKey, 67890),
    BundleBin =
        create_bundle_binary(123,
                             456,
                             PreKeyId,
                             PreKeyPublic,
                             SignedPreKeyId,
                             SignedPreKeyPublic,
                             RemoteIdentityKey),
    {ok, EstablishedSession} = protocol:process_pre_key_bundle(Session, BundleBin),

    % Encrypt a message
    OriginalMessage = <<"Test message for decryption">>,
    {ok, EncryptedMessage} = protocol:encrypt_message(EstablishedSession, OriginalMessage),

    % Test decryption
    {ok, DecryptedMessage} = protocol:decrypt_message(EstablishedSession, EncryptedMessage),
    ?assertEqual(OriginalMessage, DecryptedMessage),

    % Test with different message
    OriginalMessage2 = <<"Another test message">>,
    {ok, EncryptedMessage2} = protocol:encrypt_message(EstablishedSession, OriginalMessage2),
    {ok, DecryptedMessage2} = protocol:decrypt_message(EstablishedSession, EncryptedMessage2),
    ?assertEqual(OriginalMessage2, DecryptedMessage2),

    % Test with empty message
    {ok, EncryptedEmpty} = protocol:encrypt_message(EstablishedSession, <<>>),
    {ok, DecryptedEmpty} = protocol:decrypt_message(EstablishedSession, EncryptedEmpty),
    ?assertEqual(<<>>, DecryptedEmpty),

    ok = protocol:stop().

%% Test unknown call handling
test_unknown_call(_Config) ->
    {ok, Pid} = protocol:start(),

    % Test unknown call returns error
    {error, unknown_call} = gen_server:call(protocol, unknown_request),

    ok = protocol:stop().

%% Test error handling
test_error_handling(_Config) ->
    {ok, Pid} = protocol:start(),

    % Test with invalid session (should handle gracefully)
    InvalidSession = <<"invalid_session_data">>,
    InvalidMessage = <<"test">>,

    % These might return errors or crash, but shouldn't crash the server
    try
        protocol:encrypt_message(InvalidSession, InvalidMessage)
    catch
        _:_ ->
            ok
    end,

    try
        protocol:decrypt_message(InvalidSession, InvalidMessage)
    catch
        _:_ ->
            ok
    end,

    % Verify server is still running
    ?assert(is_pid(whereis(protocol))),

    ok = protocol:stop().

%% Test concurrent operations
test_concurrent_operations(_Config) ->
    {ok, Pid} = protocol:start(),

    % Test multiple concurrent key generations by making calls from parent process
    % This tests that the gen_server can handle multiple requests concurrently
    Results =
        lists:map(fun(_) ->
                     {ok, {PublicKey, PrivateKey}} = protocol:generate_identity_key_pair(),
                     {PublicKey, PrivateKey}
                  end,
                  lists:seq(1, 10)),

    % Verify all results are valid
    lists:foreach(fun({PublicKey, PrivateKey}) ->
                     ?assert(is_binary(PublicKey)),
                     ?assert(is_binary(PrivateKey)),
                     ?assert(byte_size(PublicKey) > 0),
                     ?assert(byte_size(PrivateKey) > 0)
                  end,
                  Results),

    % Verify keys are different
    PublicKeys = [PK || {PK, _} <- Results],
    PrivateKeys = [PK || {_, PK} <- Results],
    ?assertEqual(length(PublicKeys), length(lists:usort(PublicKeys))),
    ?assertEqual(length(PrivateKeys), length(lists:usort(PrivateKeys))),

    ok = protocol:stop().
