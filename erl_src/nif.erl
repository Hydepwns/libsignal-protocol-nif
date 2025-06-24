-module(nif).

-export([init/0, generate_identity_key_pair/0, generate_pre_key/1,
         generate_signed_pre_key/2, create_session/1, process_pre_key_bundle/2, encrypt_message/2,
         decrypt_message/2, get_cache_stats/1, reset_cache_stats/1, set_cache_size/3]).

%% @doc Initialize the NIF library
%% @returns ok | {error, Reason}
init() ->
    % Add a small delay to ensure the module is fully loaded
    timer:sleep(10),
    % Write to debug log to verify function is called
    error_logger:info_msg("[NIF DEBUG] init/0 function called"),
    % Check if NIF is already loaded
    case erlang:function_exported(?MODULE, generate_identity_key_pair, 0) of
        true ->
            % NIF is already loaded, check if it's working
            case catch ?MODULE:generate_identity_key_pair() of
                {ok, _} ->
                    error_logger:info_msg("[NIF DEBUG] NIF already loaded and working"),
                    ok;
                _ ->
                    error_logger:info_msg("[NIF DEBUG] NIF appears to be loaded but not working, attempting reload"),
                    load_nif_platform_specific()
            end;
        false ->
            % NIF not loaded, load it
            load_nif_platform_specific()
    end.

%% @private Load NIF with absolute path
load_nif_absolute(Filename) ->
    % Try to find the NIF in the code path
    case code:priv_dir(nif) of
        {error, bad_name} ->
            error_logger:info_msg("[NIF DEBUG] code:priv_dir/1 returned bad_name, trying priv/~s",
                                  [Filename]),
            % Fallback to relative path
            load_nif("priv/" ++ Filename);
        PrivDir ->
            % Convert to absolute path
            AbsPrivDir = filename:absname(PrivDir),
            % For macOS, we need to handle the extension manually
            case os:type() of
                {unix, darwin} ->
                    DylibPath = filename:join(AbsPrivDir, Filename ++ ".dylib"),
                    SoPath = filename:join(AbsPrivDir, Filename ++ ".so"),
                    % Create symlink if it doesn't exist
                    case file:read_link(SoPath) of
                        {error, enoent} ->
                            % Symlink doesn't exist, create it
                            case file:make_symlink(DylibPath, SoPath) of
                                ok ->
                                    error_logger:info_msg("[NIF DEBUG] Created symlink ~s -> ~s",
                                                          [SoPath, DylibPath]);
                                {error, SymlinkReason} ->
                                    error_logger:info_msg("[NIF DEBUG] Failed to create symlink: ~p",
                                                          [SymlinkReason])
                            end;
                        _ ->
                            % Symlink already exists
                            ok
                    end,
                    % Use base filename without extension so Erlang appends .so correctly
                    BasePath = filename:join(AbsPrivDir, Filename),
                    error_logger:info_msg("[NIF DEBUG] code:priv_dir/1 returned ~p (abs: ~s), trying ~s",
                                          [PrivDir, AbsPrivDir, BasePath]),
                    error_logger:info_msg("[NIF DEBUG] calling erlang:load_nif directly with path: ~s",
                                          [BasePath]),
                    try erlang:load_nif(BasePath, 0) of
                        ok ->
                            error_logger:info_msg("[NIF DEBUG] erlang:load_nif succeeded"),
                            ok;
                        {error, {Reason, Details}} ->
                            error_logger:info_msg("[NIF DEBUG] erlang:load_nif failed: ~p, details: ~p",
                                                  [Reason, Details]),
                            {error, {Reason, Details}};
                        {error, Reason} ->
                            error_logger:info_msg("[NIF DEBUG] erlang:load_nif failed: ~p",
                                                  [Reason]),
                            {error, Reason}
                    catch
                        Class:Error:Stacktrace ->
                            error_logger:info_msg("[NIF DEBUG] Exception during erlang:load_nif: ~p:~p~nStacktrace: ~p",
                                                  [Class, Error, Stacktrace]),
                            {error, {Class, Error, Stacktrace}}
                    end;
                _ ->
                    NifPath = filename:join(AbsPrivDir, Filename),
                    error_logger:info_msg("[NIF DEBUG] code:priv_dir/1 returned ~p (abs: ~s), trying ~s",
                                          [PrivDir, AbsPrivDir, NifPath]),
                    error_logger:info_msg("[NIF DEBUG] calling erlang:load_nif directly with path: ~s",
                                          [NifPath]),
                    try erlang:load_nif(NifPath, 0) of
                        ok ->
                            error_logger:info_msg("[NIF DEBUG] erlang:load_nif succeeded"),
                            ok;
                        {error, {Reason, Details}} ->
                            error_logger:info_msg("[NIF DEBUG] erlang:load_nif failed: ~p, details: ~p",
                                                  [Reason, Details]),
                            {error, {Reason, Details}};
                        {error, Reason} ->
                            error_logger:info_msg("[NIF DEBUG] erlang:load_nif failed: ~p",
                                                  [Reason]),
                            {error, Reason}
                    catch
                        Class:Error:Stacktrace ->
                            error_logger:info_msg("[NIF DEBUG] Exception during erlang:load_nif: ~p:~p~nStacktrace: ~p",
                                                  [Class, Error, Stacktrace]),
                            {error, {Class, Error, Stacktrace}}
                    end
            end
    end.

%% @private Load NIF with error handling
load_nif(Path) ->
    error_logger:info_msg("[NIF DEBUG] load_nif called with path: ~s", [Path]),
    try erlang:load_nif(Path, 0) of
        ok ->
            error_logger:info_msg("[NIF DEBUG] load_nif succeeded"),
            ok;
        {error, {Reason, Details}} ->
            error_logger:info_msg("[NIF DEBUG] load_nif failed with error: ~p, details: ~p",
                                  [Reason, Details]),
            {error, {Reason, Details}};
        {error, Reason} ->
            error_logger:info_msg("[NIF DEBUG] load_nif failed with error: ~p", [Reason]),
            {error, Reason}
    catch
        Class:Error:Stacktrace ->
            error_logger:info_msg("[NIF DEBUG] Exception during erlang:load_nif: ~p:~p~nStacktrace: ~p",
                                  [Class, Error, Stacktrace]),
            {error, {Class, Error, Stacktrace}}
    end.

%% @private Load NIF based on platform
load_nif_platform_specific() ->
    case os:type() of
        {unix, darwin} ->
            % On macOS, pass filename without .dylib extension to prevent .so suffix
            load_nif_absolute("nif");
        {unix, _} ->
            load_nif_absolute("nif.so");
        {win32, _} ->
            load_nif_absolute("nif.dll")
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
%% @param Session The session to update
%% @param PreKeyBundle The pre-key bundle to process
%% @returns {ok, Session} | {error, Reason}
process_pre_key_bundle(_Session, _PreKeyBundle) ->
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
