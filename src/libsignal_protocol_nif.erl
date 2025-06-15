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

init() ->
    case os:type() of
        {unix, darwin} ->
            erlang:load_nif("priv/libsignal_protocol_nif.dylib", 0);
        {unix, _} ->
            erlang:load_nif("priv/libsignal_protocol_nif.so", 0);
        {win32, _} ->
            erlang:load_nif("priv/libsignal_protocol_nif.dll", 0)
    end.

generate_identity_key_pair() ->
    erlang:nif_error(nif_not_loaded).

generate_pre_key(_IdentityKey) ->
    erlang:nif_error(nif_not_loaded).

generate_signed_pre_key(_IdentityKey, _Timestamp) ->
    erlang:nif_error(nif_not_loaded).

create_session(_IdentityKey) ->
    erlang:nif_error(nif_not_loaded).

process_pre_key_bundle(_IdentityKey, _PreKeyBundle) ->
    erlang:nif_error(nif_not_loaded).

encrypt_message(_, _) ->
    erlang:nif_error(nif_not_loaded).

decrypt_message(_, _) ->
    erlang:nif_error(nif_not_loaded).

get_cache_stats(_Session) ->
    erlang:nif_error(nif_not_loaded).

reset_cache_stats(_Session) ->
    erlang:nif_error(nif_not_loaded).

set_cache_size(_Session, _ChainKeySize, _RootKeySize) ->
    erlang:nif_error(nif_not_loaded). 