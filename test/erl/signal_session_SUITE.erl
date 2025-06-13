-module(signal_session_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(export_all).

all() ->
    [
        test_new_session,
        test_process_pre_key_bundle,
        test_encrypt_decrypt_message,
        test_invalid_bundle,
        test_invalid_message
    ].

init_per_suite(Config) ->
    % Initialize crypto
    crypto:start(),
    Config.

end_per_suite(_Config) ->
    crypto:stop(),
    ok.

test_new_session(_Config) ->
    % Generate test keys
    {LocalPublic, _} = signal_crypto:generate_key_pair(),
    {RemotePublic, _} = signal_crypto:generate_key_pair(),

    % Create new session
    Session = signal_session:new(LocalPublic, RemotePublic),

    % Verify session properties
    ?assert(is_binary(signal_session:get_session_id(Session))),
    ?assertEqual(LocalPublic, maps:get(local_identity_key, Session)),
    ?assertEqual(RemotePublic, maps:get(remote_identity_key, Session)),
    ?assertEqual(undefined, maps:get(pre_key_id, Session, undefined)),
    ?assertEqual(undefined, maps:get(signed_pre_key_id, Session, undefined)),
    ?assertEqual(undefined, maps:get(ephemeral_key, Session, undefined)),
    ?assertEqual(undefined, maps:get(chain_key, Session, undefined)),
    ?assertEqual(#{}, maps:get(message_keys, Session, #{})).

test_process_pre_key_bundle(_Config) ->
    % Generate test keys
    {LocalPublic, LocalPrivate} = signal_crypto:generate_key_pair(),
    {RemotePublic, RemotePrivate} = signal_crypto:generate_key_pair(),
    {PreKeyPublic, PreKeyPrivate} = signal_crypto:generate_key_pair(),
    {SignedPreKeyPublic, SignedPreKeyPrivate} = signal_crypto:generate_key_pair(),

    % Create pre-key bundle
    PreKeyId = 1,
    SignedPreKeyId = 2,
    RegistrationId = 123,
    DeviceId = 456,
    Signature = signal_crypto:sign(RemotePrivate, SignedPreKeyPublic),

    Bundle = {
        RegistrationId,
        DeviceId,
        {PreKeyId, PreKeyPublic},
        {SignedPreKeyId, SignedPreKeyPublic, Signature},
        RemotePublic
    },

    % Create session and process bundle
    Session = signal_session:new(LocalPublic, RemotePublic),
    {ok, UpdatedSession} = signal_session:process_pre_key_bundle(Session, Bundle),

    % Verify updated session
    ?assertEqual(PreKeyId, maps:get(pre_key_id, UpdatedSession)),
    ?assertEqual(SignedPreKeyId, maps:get(signed_pre_key_id, UpdatedSession)),
    ?assert(is_binary(maps:get(ephemeral_key, UpdatedSession))),
    ?assert(is_binary(maps:get(chain_key, UpdatedSession))).

test_encrypt_decrypt_message(_Config) ->
    % Generate test keys
    {LocalPublic, LocalPrivate} = signal_crypto:generate_key_pair(),
    {RemotePublic, RemotePrivate} = signal_crypto:generate_key_pair(),
    {PreKeyPublic, PreKeyPrivate} = signal_crypto:generate_key_pair(),
    {SignedPreKeyPublic, SignedPreKeyPrivate} = signal_crypto:generate_key_pair(),

    % Create pre-key bundle
    PreKeyId = 1,
    SignedPreKeyId = 2,
    RegistrationId = 123,
    DeviceId = 456,
    Signature = signal_crypto:sign(RemotePrivate, SignedPreKeyPublic),

    Bundle = {
        RegistrationId,
        DeviceId,
        {PreKeyId, PreKeyPublic},
        {SignedPreKeyId, SignedPreKeyPublic, Signature},
        RemotePublic
    },

    % Create session and process bundle
    Session = signal_session:new(LocalPublic, RemotePublic),
    {ok, UpdatedSession} = signal_session:process_pre_key_bundle(Session, Bundle),

    % Test message
    TestMessage = <<"Hello, Signal Protocol!">>,

    % Encrypt message
    {ok, EncryptedMessage, EncryptedSession} = signal_session:encrypt(UpdatedSession, TestMessage),

    % Decrypt message
    {ok, DecryptedMessage, _} = signal_session:decrypt(EncryptedSession, EncryptedMessage),

    % Verify decrypted message
    ?assertEqual(TestMessage, DecryptedMessage).

test_invalid_bundle(_Config) ->
    % Generate test keys
    {LocalPublic, _} = signal_crypto:generate_key_pair(),
    {RemotePublic, _} = signal_crypto:generate_key_pair(),
    {PreKeyPublic, _} = signal_crypto:generate_key_pair(),
    {SignedPreKeyPublic, _} = signal_crypto:generate_key_pair(),

    % Create invalid bundle with wrong signature
    PreKeyId = 1,
    SignedPreKeyId = 2,
    RegistrationId = 123,
    DeviceId = 456,
    InvalidSignature = <<0:256>>, % All zeros signature

    Bundle = {
        RegistrationId,
        DeviceId,
        {PreKeyId, PreKeyPublic},
        {SignedPreKeyId, SignedPreKeyPublic, InvalidSignature},
        RemotePublic
    },

    % Create session and try to process invalid bundle
    Session = signal_session:new(LocalPublic, RemotePublic),
    {error, invalid_signature} = signal_session:process_pre_key_bundle(Session, Bundle).

test_invalid_message(_Config) ->
    % Generate test keys
    {LocalPublic, _} = signal_crypto:generate_key_pair(),
    {RemotePublic, _} = signal_crypto:generate_key_pair(),

    % Create session
    Session = signal_session:new(LocalPublic, RemotePublic),

    % Try to decrypt invalid message
    InvalidMessage = <<0:1000>>, % Random bytes
    {error, {decryption_failed, _}} = signal_session:decrypt(Session, InvalidMessage). 