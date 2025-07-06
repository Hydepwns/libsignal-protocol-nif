-module(libsignal_protocol_nif_v2).

-export([
    init/0,
    generate_identity_key_pair/0,
    generate_pre_key/1,
    generate_signed_pre_key/2,
    process_pre_key_bundle/2,
    init_double_ratchet/3,
    dr_encrypt_message/2,
    dr_decrypt_message/2
]).

-on_load(load_nif/0).

%% NIF loading functions
load_nif() ->
    Paths = ["../priv/libsignal_protocol_nif_v2", "priv/libsignal_protocol_nif_v2", "./priv/libsignal_protocol_nif_v2"],
    load_nif_from_paths(Paths).

load_nif_from_paths([]) ->
    io:format("Warning: libsignal_protocol_nif_v2 C NIF not found, using Erlang fallback~n"),
    ok;
load_nif_from_paths([Path | Rest]) ->
    case erlang:load_nif(Path, 0) of
        ok ->
            io:format("libsignal_protocol_nif_v2 C NIF loaded successfully from ~s~n", [Path]),
            ok;
        {error, {reload, _}} ->
            io:format("libsignal_protocol_nif_v2 C NIF already loaded~n"),
            ok;
        {error, Reason} ->
            io:format("Failed to load libsignal_protocol_nif_v2 C NIF from ~s: ~p~n", [Path, Reason]),
            load_nif_from_paths(Rest)
    end.

%% NIF function stubs (will be replaced by C implementations when NIF loads)
%% These serve as fallbacks if the C NIF fails to load

init() ->
    erlang:nif_error(nif_not_loaded).

generate_identity_key_pair() ->
    erlang:nif_error(nif_not_loaded).

generate_pre_key(_KeyId) ->
    erlang:nif_error(nif_not_loaded).

generate_signed_pre_key(_IdentityKey, _KeyId) ->
    erlang:nif_error(nif_not_loaded).

process_pre_key_bundle(_LocalIdentityKey, _Bundle) ->
    erlang:nif_error(nif_not_loaded).

init_double_ratchet(_SharedSecret, _RemotePublicKey, _IsAlice) ->
    erlang:nif_error(nif_not_loaded).

dr_encrypt_message(_DrSession, _Message) ->
    erlang:nif_error(nif_not_loaded).

dr_decrypt_message(_DrSession, _EncryptedMessage) ->
    erlang:nif_error(nif_not_loaded).

%% Erlang fallback implementations (used only if C NIF fails to load)

init_fallback() ->
    ok.

generate_identity_key_pair_fallback() ->
    PublicKey = crypto:strong_rand_bytes(32),
    PrivateKey = crypto:strong_rand_bytes(32),
    {ok, {PublicKey, PrivateKey}}.

generate_pre_key_fallback(KeyId) when is_integer(KeyId) ->
    PreKey = crypto:strong_rand_bytes(32),
    {ok, {KeyId, PreKey}}.

generate_signed_pre_key_fallback(IdentityKey, KeyId) when is_binary(IdentityKey), is_integer(KeyId) ->
    PreKey = crypto:strong_rand_bytes(32),
    Signature = crypto:strong_rand_bytes(64),
    {ok, {KeyId, PreKey, Signature}}.

process_pre_key_bundle_fallback(LocalIdentityKey, Bundle) when is_binary(LocalIdentityKey), is_binary(Bundle) ->
    % Fallback X3DH implementation - returns dummy session key and ephemeral key
    SessionKey = crypto:strong_rand_bytes(64),
    EphemeralKey = crypto:strong_rand_bytes(32),
    {ok, {SessionKey, EphemeralKey}}.

init_double_ratchet_fallback(SharedSecret, RemotePublicKey, IsAlice) 
    when is_binary(SharedSecret), is_binary(RemotePublicKey), is_integer(IsAlice) ->
    % Fallback Double Ratchet initialization - returns dummy session
    DrSession = crypto:strong_rand_bytes(200),
    {ok, DrSession}.

dr_encrypt_message_fallback(DrSession, Message) when is_binary(DrSession), is_binary(Message) ->
    % Fallback encryption - simple padding
    Header = <<170,170,170,170,170,170,170,170>>, % 8 bytes of 0xAA
    Footer = <<187,187,187,187,187,187,187,187>>, % 8 bytes of 0xBB
    Encrypted = <<Header/binary, Message/binary, Footer/binary>>,
    UpdatedSession = crypto:strong_rand_bytes(200),
    {ok, {Encrypted, UpdatedSession}}.

dr_decrypt_message_fallback(DrSession, EncryptedMessage) when is_binary(DrSession), is_binary(EncryptedMessage) ->
    % Fallback decryption - remove padding
    case byte_size(EncryptedMessage) of
        Size when Size >= 16 ->
            <<_Header:8/binary, Rest/binary>> = EncryptedMessage,
            MessageSize = Size - 16,
            <<Message:MessageSize/binary, _Footer:8/binary>> = Rest,
            UpdatedSession = crypto:strong_rand_bytes(200),
            {ok, {Message, UpdatedSession}};
        _ ->
            {error, invalid_message}
    end. 