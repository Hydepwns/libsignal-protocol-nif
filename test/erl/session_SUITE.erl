-module(session_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(export_all).

all() ->
    [test_new_session,
     test_process_pre_key_bundle,
     test_encrypt_decrypt_message,
     test_invalid_bundle,
     test_invalid_message].

init_per_suite(Config) ->
    io:format("session_SUITE: init_per_suite starting~n", []),
    % Start the application to ensure priv_dir is available
    application:ensure_all_started(nif),
    % Initialize crypto
    crypto:start(),
    % Initialize the NIF
    case nif:init() of
        ok ->
            io:format("NIF initialized successfully~n"),
            Config;
        {error, Reason} ->
            io:format("Failed to initialize NIF: ~p~n", [Reason]),
            {skip, "NIF initialization failed"}
    end.

end_per_suite(_Config) ->
    crypto:stop(),
    ok.

test_new_session(_Config) ->
    % Generate test keys
    {ok, {LocalPublic, _}} = crypto:generate_key_pair(),
    {ok, {RemotePublic, _}} = crypto:generate_key_pair(),

    % Create new session
    Session = session:new(LocalPublic, RemotePublic),

    % Verify session properties
    ?assert(is_binary(session:get_session_id(Session))),
    ?assertEqual(LocalPublic, maps:get(local_identity_key, Session)),
    ?assertEqual(RemotePublic, maps:get(remote_identity_key, Session)),
    ?assertEqual(undefined, maps:get(pre_key_id, Session)),
    ?assertEqual(undefined, maps:get(signed_pre_key_id, Session)),
    ?assertEqual(undefined, maps:get(ephemeral_key, Session, undefined)),
    ?assertEqual(undefined, maps:get(chain_key, Session, undefined)),
    ?assertEqual(#{}, maps:get(message_keys, Session, #{})).

test_process_pre_key_bundle(_Config) ->
    % Generate test keys
    {ok, {LocalPublic, LocalPrivate}} = crypto:generate_key_pair(),
    file:write_file("/tmp/signal_test_debug.log", "Generated LocalPublic key\n", [append]),
    {ok, {RemotePublic, RemotePrivate}} = crypto:generate_key_pair(),
    file:write_file("/tmp/signal_test_debug.log", "Generated RemotePublic key\n", [append]),
    {ok, {PreKeyPublic, PreKeyPrivate}} = crypto:generate_key_pair(),
    file:write_file("/tmp/signal_test_debug.log", "Generated PreKeyPublic key\n", [append]),
    {ok, {SignedPreKeyPublic, SignedPreKeyPrivate}} = crypto:generate_key_pair(),
    file:write_file("/tmp/signal_test_debug.log",
                    "Generated SignedPreKeyPublic key\n",
                    [append]),

    % Create pre-key bundle
    PreKeyId = 1,
    SignedPreKeyId = 2,
    RegistrationId = 123,
    DeviceId = 456,
    RemotePublic32 = binary:part(RemotePublic, 0, 32),
    SignedPreKeyPublic32 = binary:part(SignedPreKeyPublic, 0, 32),
    io:format("RemotePublic: ~p (~p bytes)~n", [RemotePublic32, byte_size(RemotePublic32)]),
    io:format("SignedPreKeyPublic: ~p (~p bytes)~n",
              [SignedPreKeyPublic32, byte_size(SignedPreKeyPublic32)]),
    {ok, Signature} = crypto:sign(RemotePublic32, SignedPreKeyPublic32),
    file:write_file("/tmp/signal_test_debug.log", "Generated signature\n", [append]),

    Bundle =
        {RegistrationId,
         DeviceId,
         {PreKeyId, PreKeyPublic},
         {SignedPreKeyId, SignedPreKeyPublic, Signature},
         RemotePublic},

    % Create session and process bundle
    Session = session:new(LocalPublic, RemotePublic),
    file:write_file("/tmp/signal_test_debug.log", "Created session\n", [append]),
    {ok, UpdatedSession} = session:process_pre_key_bundle(Session, Bundle),
    file:write_file("/tmp/signal_test_debug.log", "Processed bundle\n", [append]),

    % Verify updated session
    ?assertEqual(PreKeyId, maps:get(pre_key_id, UpdatedSession)),
    ?assertEqual(SignedPreKeyId, maps:get(signed_pre_key_id, UpdatedSession)),
    ?assert(is_binary(maps:get(ephemeral_key, UpdatedSession))),
    ?assert(is_binary(maps:get(chain_key, UpdatedSession))).

test_encrypt_decrypt_message(_Config) ->
    file:write_file("/tmp/signal_test_debug.log",
                    "test_encrypt_decrypt_message: starting\n",
                    [append]),
    % Generate test keys
    {ok, {LocalPublic, LocalPrivate}} = crypto:generate_key_pair(),
    file:write_file("/tmp/signal_test_debug.log", "Generated LocalPublic key\n", [append]),
    {ok, {RemotePublic, RemotePrivate}} = crypto:generate_key_pair(),
    file:write_file("/tmp/signal_test_debug.log", "Generated RemotePublic key\n", [append]),
    {ok, {PreKeyPublic, PreKeyPrivate}} = crypto:generate_key_pair(),
    file:write_file("/tmp/signal_test_debug.log", "Generated PreKeyPublic key\n", [append]),
    {ok, {SignedPreKeyPublic, SignedPreKeyPrivate}} = crypto:generate_key_pair(),
    file:write_file("/tmp/signal_test_debug.log",
                    "Generated SignedPreKeyPublic key\n",
                    [append]),

    % Create pre-key bundle
    PreKeyId = 1,
    SignedPreKeyId = 2,
    RegistrationId = 123,
    DeviceId = 456,
    RemotePublic32 = binary:part(RemotePublic, 0, 32),
    SignedPreKeyPublic32 = binary:part(SignedPreKeyPublic, 0, 32),
    io:format("RemotePublic: ~p (~p bytes)~n", [RemotePublic32, byte_size(RemotePublic32)]),
    io:format("SignedPreKeyPublic: ~p (~p bytes)~n",
              [SignedPreKeyPublic32, byte_size(SignedPreKeyPublic32)]),
    {ok, Signature} = crypto:sign(RemotePublic32, SignedPreKeyPublic32),

    Bundle =
        {RegistrationId,
         DeviceId,
         {PreKeyId, PreKeyPublic},
         {SignedPreKeyId, SignedPreKeyPublic, Signature},
         RemotePublic},

    % Create session and process bundle
    Session = session:new(LocalPublic, RemotePublic),
    {ok, UpdatedSession} = session:process_pre_key_bundle(Session, Bundle),

    % Test message
    TestMessage = <<"Hello, Signal Protocol!">>,

    % Encrypt message
    {ok, EncryptedMessage, EncryptedSession} = session:encrypt(UpdatedSession, TestMessage),

    % Decrypt message
    {ok, DecryptedMessage, _} = session:decrypt(EncryptedSession, EncryptedMessage),

    % Verify decrypted message
    ?assertEqual(TestMessage, DecryptedMessage).

test_invalid_bundle(_Config) ->
    % Generate test keys
    {ok, {LocalPublic, _}} = crypto:generate_key_pair(),
    {ok, {RemotePublic, _}} = crypto:generate_key_pair(),
    {ok, {PreKeyPublic, _}} = crypto:generate_key_pair(),
    {ok, {SignedPreKeyPublic, _}} = crypto:generate_key_pair(),

    % Create invalid bundle with wrong signature
    PreKeyId = 1,
    SignedPreKeyId = 2,
    RegistrationId = 123,
    DeviceId = 456,
    InvalidSignature = <<0:256>>, % All zeros signature

    Bundle =
        {RegistrationId,
         DeviceId,
         {PreKeyId, PreKeyPublic},
         {SignedPreKeyId, SignedPreKeyPublic, InvalidSignature},
         RemotePublic},

    % Create session and try to process invalid bundle
    Session = session:new(LocalPublic, RemotePublic),
    {error, invalid_signature} = session:process_pre_key_bundle(Session, Bundle).

test_invalid_message(_Config) ->
    % Generate test keys
    {ok, {LocalPublic, _}} = crypto:generate_key_pair(),
    {ok, {RemotePublic, _}} = crypto:generate_key_pair(),

    % Create session
    Session = session:new(LocalPublic, RemotePublic),

    % Try to decrypt invalid message
    InvalidMessage = <<0:1000>>, % Random bytes
    {error, {decryption_failed, _}} = session:decrypt(Session, InvalidMessage).
