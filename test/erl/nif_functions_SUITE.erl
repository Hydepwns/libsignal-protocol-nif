-module(nif_functions_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(export_all).

all() ->
    [test_generate_identity_key_pair,
     test_generate_pre_key,
     test_generate_signed_pre_key,
     test_create_session,
     test_process_pre_key_bundle,
     test_encrypt_decrypt_message,
     test_cache_operations,
     test_error_handling,
     test_concurrent_operations,
     test_large_messages,
     test_key_validation,
     test_session_persistence].

init_per_suite(Config) ->
    io:format("nif_functions_SUITE: init_per_suite starting~n", []),
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

test_generate_identity_key_pair(_Config) ->
    % Test basic key generation
    {ok, {PublicKey, PrivateKey}} = nif:generate_identity_key_pair(),
    ?assert(is_binary(PublicKey)),
    ?assert(is_binary(PrivateKey)),
    ?assertEqual(32, byte_size(PublicKey)),
    ?assertEqual(32, byte_size(PrivateKey)),

    % Test that keys are different
    ?assertNotEqual(PublicKey, PrivateKey),

    % Test multiple key generations produce different keys
    {ok, {PublicKey2, PrivateKey2}} = nif:generate_identity_key_pair(),
    ?assertNotEqual(PublicKey, PublicKey2),
    ?assertNotEqual(PrivateKey, PrivateKey2).

test_generate_pre_key(_Config) ->
    % Test pre-key generation with different IDs
    KeyIds = [1, 100, 1000, 65535],
    Keys = [],

    Keys =
        [begin
             {ok, {KeyId, PreKey}} = nif:generate_pre_key(KeyId),
             ?assert(is_binary(PreKey)),
             ?assertEqual(32, byte_size(PreKey)),
             {KeyId, PreKey}
         end
         || KeyId <- KeyIds],

    % Verify all keys are different
    PreKeys = [PreKey || {_KeyId, PreKey} <- Keys],
    UniqueKeys = sets:from_list(PreKeys),
    ?assertEqual(length(PreKeys), sets:size(UniqueKeys)).

test_generate_signed_pre_key(_Config) ->
    % Generate identity key for signing
    {ok, {IdentityPublic, IdentityPrivate}} = nif:generate_identity_key_pair(),

    % Test signed pre-key generation
    KeyIds = [1, 100, 1000],
    SignedKeys = [],

    SignedKeys =
        [begin
             {ok, {KeyId, SignedPreKey, Signature}} =
                 nif:generate_signed_pre_key(IdentityPrivate, KeyId),
             ?assert(is_binary(SignedPreKey)),
             ?assert(is_binary(Signature)),
             ?assertEqual(32, byte_size(SignedPreKey)),
             ?assertEqual(64, byte_size(Signature)), % ECDSA signature size
             {KeyId, SignedPreKey, Signature}
         end
         || KeyId <- KeyIds],

    % Verify all signed keys are different
    SignedPreKeys = [SignedPreKey || {_KeyId, SignedPreKey, _Signature} <- SignedKeys],
    UniqueSignedKeys = sets:from_list(SignedPreKeys),
    ?assertEqual(length(SignedPreKeys), sets:size(UniqueSignedKeys)).

test_create_session(_Config) ->
    % Generate identity key
    {ok, {IdentityKey, _}} = nif:generate_identity_key_pair(),

    % Test session creation
    {ok, Session} = nif:create_session(IdentityKey),
    ?assert(is_binary(Session)),
    ?assert(byte_size(Session) > 0).

test_process_pre_key_bundle(_Config) ->
    % Generate keys for bundle
    {ok, {IdentityKey, _}} = nif:generate_identity_key_pair(),
    {ok, {PreKeyId, PreKey}} = nif:generate_pre_key(1),
    {ok, {SignedPreKeyId, SignedPreKey, Signature}} =
        nif:generate_signed_pre_key(IdentityKey, 2),

    % Create session
    {ok, Session} = nif:create_session(IdentityKey),

    % Create pre-key bundle
    Bundle =
        {123, 456, {PreKeyId, PreKey}, {SignedPreKeyId, SignedPreKey, Signature}, IdentityKey},

    % Process bundle
    {ok, UpdatedSession} = nif:process_pre_key_bundle(Session, Bundle),
    ?assert(is_binary(UpdatedSession)),
    ?assertNotEqual(Session, UpdatedSession).

test_encrypt_decrypt_message(_Config) ->
    % Generate keys and create session
    {ok, {IdentityKey, _}} = nif:generate_identity_key_pair(),
    {ok, {PreKeyId, PreKey}} = nif:generate_pre_key(1),
    {ok, {SignedPreKeyId, SignedPreKey, Signature}} =
        nif:generate_signed_pre_key(IdentityKey, 2),
    {ok, Session} = nif:create_session(IdentityKey),

    % Process bundle to establish session
    Bundle =
        {123, 456, {PreKeyId, PreKey}, {SignedPreKeyId, SignedPreKey, Signature}, IdentityKey},
    {ok, EstablishedSession} = nif:process_pre_key_bundle(Session, Bundle),

    % Test various message sizes
    Messages =
        [<<"Hello, Signal Protocol!">>,
         <<"Short">>,
         binary:copy(<<"A">>, 1000),
         binary:copy(<<"B">>, 10000),
         crypto:strong_rand_bytes(5000)],

    [begin
         % Encrypt message
         {ok, EncryptedMessage} = nif:encrypt_message(EstablishedSession, Message),
         ?assert(is_binary(EncryptedMessage)),
         ?assert(byte_size(EncryptedMessage) > 0),

         % Decrypt message
         {ok, DecryptedMessage} = nif:decrypt_message(EstablishedSession, EncryptedMessage),
         ?assertEqual(Message, DecryptedMessage)
     end
     || Message <- Messages].

test_cache_operations(_Config) ->
    % Generate keys and create session
    {ok, {IdentityKey, _}} = nif:generate_identity_key_pair(),
    {ok, Session} = nif:create_session(IdentityKey),

    % Test cache statistics
    {ok, Stats} = nif:get_cache_stats(Session),
    ?assert(is_map(Stats)),

    % Test cache size configuration
    {ok, UpdatedStats} = nif:set_cache_size(Session, 10, 5),
    ?assert(is_map(UpdatedStats)),

    % Test cache reset
    {ok, ResetStats} = nif:reset_cache_stats(Session),
    ?assert(is_map(ResetStats)).

test_error_handling(_Config) ->
    % Test invalid inputs
    ?assertMatch({error, _}, nif:generate_pre_key(-1)),
    ?assertMatch({error, _}, nif:generate_signed_pre_key(<<>>, 1)),
    ?assertMatch({error, _}, nif:create_session(<<>>)),

    % Test invalid session operations
    InvalidSession = <<"invalid_session_data">>,
    ?assertMatch({error, _}, nif:encrypt_message(InvalidSession, <<"test">>)),
    ?assertMatch({error, _}, nif:decrypt_message(InvalidSession, <<"test">>)),
    ?assertMatch({error, _}, nif:get_cache_stats(InvalidSession)).

test_concurrent_operations(_Config) ->
    % Test concurrent key generation
    NumProcesses = 10,
    NumKeysPerProcess = 10,

    Pids =
        [spawn(fun() ->
                  Keys =
                      [begin
                           {ok, {PublicKey, PrivateKey}} = nif:generate_identity_key_pair(),
                           {PublicKey, PrivateKey}
                       end
                       || _ <- lists:seq(1, NumKeysPerProcess)],
                  exit({keys, Keys})
               end)
         || _ <- lists:seq(1, NumProcesses)],

    Results =
        [receive
             {'EXIT', Pid, {keys, Keys}} ->
                 Keys
         end
         || Pid <- Pids],

    % Verify all keys are unique
    AllKeys = lists:flatten(Results),
    PublicKeys = [PublicKey || {PublicKey, _} <- AllKeys],
    UniquePublicKeys = sets:from_list(PublicKeys),
    ?assertEqual(length(PublicKeys), sets:size(UniquePublicKeys)).

test_large_messages(_Config) ->
    % Generate keys and create session
    {ok, {IdentityKey, _}} = nif:generate_identity_key_pair(),
    {ok, {PreKeyId, PreKey}} = nif:generate_pre_key(1),
    {ok, {SignedPreKeyId, SignedPreKey, Signature}} =
        nif:generate_signed_pre_key(IdentityKey, 2),
    {ok, Session} = nif:create_session(IdentityKey),

    % Process bundle
    Bundle =
        {123, 456, {PreKeyId, PreKey}, {SignedPreKeyId, SignedPreKey, Signature}, IdentityKey},
    {ok, EstablishedSession} = nif:process_pre_key_bundle(Session, Bundle),

    % Test large messages
    LargeMessages =
        [crypto:strong_rand_bytes(100000),  % 100KB
         crypto:strong_rand_bytes(500000),  % 500KB
         crypto:strong_rand_bytes(1000000)],  % 1MB

    [begin
         {ok, Encrypted} = nif:encrypt_message(EstablishedSession, Message),
         {ok, Decrypted} = nif:decrypt_message(EstablishedSession, Encrypted),
         ?assertEqual(Message, Decrypted)
     end
     || Message <- LargeMessages].

test_key_validation(_Config) ->
    % Test key validation with invalid keys
    InvalidKeys =
        [<<>>,                    % Empty key
         <<1, 2, 3>>,            % Too short
         crypto:strong_rand_bytes(64),  % Too long
         binary:copy(<<0>>, 32)],   % All zeros

    [begin
         ?assertMatch({error, _}, nif:create_session(InvalidKey)),
         ?assertMatch({error, _}, nif:generate_signed_pre_key(InvalidKey, 1))
     end
     || InvalidKey <- InvalidKeys].

test_session_persistence(_Config) ->
    % Generate keys and create session
    {ok, {IdentityKey, _}} = nif:generate_identity_key_pair(),
    {ok, {PreKeyId, PreKey}} = nif:generate_pre_key(1),
    {ok, {SignedPreKeyId, SignedPreKey, Signature}} =
        nif:generate_signed_pre_key(IdentityKey, 2),
    {ok, Session} = nif:create_session(IdentityKey),

    % Process bundle
    Bundle =
        {123, 456, {PreKeyId, PreKey}, {SignedPreKeyId, SignedPreKey, Signature}, IdentityKey},
    {ok, EstablishedSession} = nif:process_pre_key_bundle(Session, Bundle),

    % Test multiple encrypt/decrypt operations with same session
    Messages = [crypto:strong_rand_bytes(100) || _ <- lists:seq(1, 10)],

    EncryptedMessages =
        [begin
             {ok, Encrypted} = nif:encrypt_message(EstablishedSession, Message),
             Encrypted
         end
         || Message <- Messages],

    % Decrypt all messages
    [begin
         {ok, Decrypted} = nif:decrypt_message(EstablishedSession, Encrypted),
         ?assertEqual(Message, Decrypted)
     end
     || {Message, Encrypted} <- lists:zip(Messages, EncryptedMessages)].
