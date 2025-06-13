-module(signal_nif).
-on_load(init/0).

-export([
    generate_identity_key_pair/0,
    generate_pre_key/1,
    generate_signed_pre_key/2,
    create_session/2,
    process_pre_key_bundle/2,
    encrypt_message/2,
    decrypt_message/2,
    sign_data/2,
    verify_signature/3,
    encrypt_message/3,
    decrypt_message/3,
    hmac_sha256/2,
    sha256/1,
    random_bytes/1
]).

-define(APPNAME, libsignal_protocol_nif).
-define(LIBNAME, libsignal_protocol_nif).

%% @doc Initialize the NIF library
init() ->
    SoName = case code:priv_dir(?APPNAME) of
        {error, bad_name} ->
            case filelib:is_dir(filename:join(["..", priv])) of
                true ->
                    filename:join(["..", priv, ?LIBNAME]);
                _ ->
                    case filelib:is_dir(filename:join(["..", "..", priv])) of
                        true ->
                            filename:join(["..", "..", priv, ?LIBNAME]);
                        _ ->
                            case filelib:is_dir(filename:join(["_build", "test", "lib", ?APPNAME, "priv"])) of
                                true ->
                                    filename:join(["_build", "test", "lib", ?APPNAME, "priv", ?LIBNAME]);
                                _ ->
                                    filename:join([priv, ?LIBNAME])
                            end
                    end
            end;
        Dir ->
            filename:join(Dir, ?LIBNAME)
    end,
    erlang:load_nif(SoName, 0).

%% @doc Generate a new identity key pair
generate_identity_key_pair() ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Generate a new pre-key with the given ID
generate_pre_key(KeyId) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Generate a new signed pre-key with the given ID
generate_signed_pre_key(IdentityKey, KeyId) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Create a new session with the given local and remote identity keys
create_session(LocalIdentityKey, RemoteIdentityKey) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Process a pre-key bundle to establish a session
process_pre_key_bundle(Session, Bundle) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Encrypt a message using the given session
encrypt_message(Session, Message) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Decrypt a message using the given session
decrypt_message(Session, Ciphertext) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Sign data with a private key
sign_data(PrivateKey, Data) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Verify a signature with a public key
verify_signature(PublicKey, Data, Signature) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Encrypt data with a key and IV
encrypt_message(Key, IV, Data) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Decrypt data with a key and IV
decrypt_message(Key, IV, Ciphertext) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Generate an HMAC of data with a key
hmac_sha256(Key, Data) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Generate a SHA-256 hash of data
sha256(Data) ->
    erlang:nif_error(nif_library_not_loaded).

%% @doc Generate random bytes
random_bytes(N) ->
    erlang:nif_error(nif_library_not_loaded). 