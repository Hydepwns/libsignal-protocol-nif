-module(libsignal_protocol_nif).

-export([
  init/0,
  generate_identity_key_pair/0,
  generate_pre_key/1,
  generate_signed_pre_key/2,
  create_session/1,
  process_pre_key_bundle/2,
  encrypt_message/2,
  decrypt_message/2,
  get_cache_stats/1,
  reset_cache_stats/1,
  set_cache_size/3
]).

-on_load(init/0).

%% @doc Initialize the NIF library
%% @returns ok | {error, Reason}
init() ->
    case os:type() of
        {unix, darwin} ->
            load_nif("priv/libsignal_protocol_nif.dylib");
        {unix, _} ->
            load_nif("priv/libsignal_protocol_nif.so");
        {win32, _} ->
            load_nif("priv/libsignal_protocol_nif.dll")
    end.

%% @private Load NIF with error handling
load_nif(Path) ->
    case erlang:load_nif(Path, 0) of
        ok -> ok;
        {error, {Reason, _}} -> {error, Reason};
        {error, Reason} -> {error, Reason}
    end.

%% @doc Generate a new identity key pair
%% @returns {ok, {PublicKey, PrivateKey}} | {error, Reason}
generate_identity_key_pair() ->
    erlang:nif_error(nif_not_loaded).

%% @doc Generate a new pre-key with the given ID
%% @param KeyId The ID for the pre-key
%% @returns {ok, {KeyId, PublicKey}} | {error, Reason}
generate_pre_key(_KeyId) ->
    erlang:nif_error(nif_not_loaded).

%% @doc Generate a new signed pre-key with the given ID
%% @param IdentityKey The identity key to sign with
%% @param KeyId The ID for the signed pre-key
%% @returns {ok, {KeyId, PublicKey, Signature}} | {error, Reason}
generate_signed_pre_key(_IdentityKey, _KeyId) ->
    erlang:nif_error(nif_not_loaded).

%% @doc Create a new session
%% @param IdentityKey The identity key for the session
%% @returns {ok, Session} | {error, Reason}
create_session(_IdentityKey) ->
    erlang:nif_error(nif_not_loaded).

%% @doc Process a pre-key bundle to establish a session
%% @param IdentityKey The identity key
%% @param PreKeyBundle The pre-key bundle to process
%% @returns {ok, Session} | {error, Reason}
process_pre_key_bundle(_IdentityKey, _PreKeyBundle) ->
    erlang:nif_error(nif_not_loaded).

%% @doc Encrypt a message using the given session
%% @param Session The session to use for encryption
%% @param Message The message to encrypt
%% @returns {ok, EncryptedMessage} | {error, Reason}
encrypt_message(_Session, _Message) ->
    erlang:nif_error(nif_not_loaded).

%% @doc Decrypt a message using the given session
%% @param Session The session to use for decryption
%% @param EncryptedMessage The encrypted message to decrypt
%% @returns {ok, DecryptedMessage} | {error, Reason}
decrypt_message(_Session, _EncryptedMessage) ->
    erlang:nif_error(nif_not_loaded).

%% @doc Get cache statistics for a session
%% @param Session The session to get stats for
%% @returns {ok, Stats} | {error, Reason}
get_cache_stats(_Session) ->
    erlang:nif_error(nif_not_loaded).

%% @doc Reset cache statistics for a session
%% @param Session The session to reset stats for
%% @returns {ok, Stats} | {error, Reason}
reset_cache_stats(_Session) ->
    erlang:nif_error(nif_not_loaded).

%% @doc Set cache sizes for a session
%% @param Session The session to configure
%% @param ChainKeySize The chain key cache size
%% @param RootKeySize The root key cache size
%% @returns {ok, Stats} | {error, Reason}
set_cache_size(_Session, _ChainKeySize, _RootKeySize) ->
    erlang:nif_error(nif_not_loaded). 