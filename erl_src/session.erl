-module(session).

-export([new/2, process_pre_key_bundle/2, encrypt/2, decrypt/2, get_session_id/1]).

-include_lib("erl_src/include/signal_types.hrl").

%% @doc Create a new session
new(LocalIdentityKey, RemoteIdentityKey) ->
    {ok, SessionId} = crypto:random_bytes(32),
    #{id => SessionId,
      local_identity_key => LocalIdentityKey,
      remote_identity_key => RemoteIdentityKey,
      pre_key_id => undefined,
      signed_pre_key_id => undefined,
      ephemeral_key => undefined,
      chain_key => undefined,
      message_keys => #{}}.

%% @doc Process a pre-key bundle to establish a session
process_pre_key_bundle(Session, Bundle) ->
    io:format("process_pre_key_bundle: starting with Bundle ~p~n", [Bundle]),
    {RegistrationId,
     DeviceId,
     {PreKeyId, PreKeyPublic},
     {SignedPreKeyId, SignedPreKeyPublic, Signature},
     IdentityKey} =
        Bundle,

    % Verify the signature before proceeding
    case verify_bundle_signature(IdentityKey, SignedPreKeyPublic, Signature) of
        {ok, true} ->
            EncodedPreKeyPublic = encode_bin(PreKeyPublic),
            EncodedSignedPreKeyPublic = encode_bin(SignedPreKeyPublic),
            EncodedIdentityKey = encode_bin(IdentityKey),

            % Convert bundle tuple to binary format expected by NIF
            BundleBinary =
                <<RegistrationId:32,
                  DeviceId:32,
                  PreKeyId:32,
                  EncodedPreKeyPublic/binary,
                  SignedPreKeyId:32,
                  EncodedSignedPreKeyPublic/binary,
                  EncodedIdentityKey/binary>>,

            % Create a dummy binary session for the NIF (it doesn't actually use the session parameter)
            DummySession = <<0:1024>>, % 1KB of zeros as placeholder

            case nif:process_pre_key_bundle(DummySession, BundleBinary) of
                {ok, {RegId, DevId, PKId, PKPub, SPKId, SPKPub, IdKey, EphKey, ChainKey}} ->
                    % Convert the NIF response to a session record
                    UpdatedSession =
                        Session#{pre_key_id => PKId,
                                 signed_pre_key_id => SPKId,
                                 ephemeral_key => EphKey,
                                 chain_key => ChainKey},
                    {ok, UpdatedSession};
                {error, Reason} ->
                    {error, Reason}
            end;
        _ ->
            {error, invalid_signature}
    end.

%% @doc Encrypt a message using the session
encrypt(Session, Message) ->
    try
        ChainKey = maps:get(chain_key, Session),
        MessageKeys = maps:get(message_keys, Session, #{}),

        % Generate new message key
        {NewChainKey, MessageKey} = derive_message_key(ChainKey),

        % Encrypt the message
        {ok, IV} = crypto:random_bytes(12),

        % Debug print to file
        ok =
            file:write_file("/tmp/signal_crypto_debug.log",
                            io_lib:format("Encrypting:~n  MessageKey: ~p (~p bytes)~n  IV: ~p (~p bytes)~n  Message: ~p (~p bytes)~n",
                                          [MessageKey,
                                           byte_size(MessageKey),
                                           IV,
                                           byte_size(IV),
                                           Message,
                                           byte_size(Message)]),
                            [append]),

        {ok, Ciphertext} = crypto:encrypt(MessageKey, IV, Message),

        % Create message header
        Header = create_message_header(Session),

        % Update session
        UpdatedSession =
            Session#{chain_key := NewChainKey,
                     message_keys := maps:put(MessageKey, true, MessageKeys)},

        % Combine header and ciphertext
        EncryptedMessage = <<Header/binary, IV/binary, Ciphertext/binary>>,

        {ok, EncryptedMessage, UpdatedSession}
    catch
        _:Reason ->
            {error, {encryption_failed, Reason}}
    end.

%% @doc Decrypt a message using the session
decrypt(Session, Ciphertext) ->
    try
        % Extract message components
        <<Header:32/binary, IV:12/binary, EncryptedData/binary>> = Ciphertext,

        % Verify message header
        case verify_message_header(Session, Header) of
            true ->
                % Derive message key
                ChainKey = maps:get(chain_key, Session),
                {NewChainKey, MessageKey} = derive_message_key(ChainKey),

                % Decrypt the message
                {ok, Message} = crypto:decrypt(MessageKey, IV, EncryptedData),

                % Update session
                MessageKeys = maps:get(message_keys, Session, #{}),
                UpdatedSession =
                    Session#{chain_key := NewChainKey,
                             message_keys := maps:put(MessageKey, true, MessageKeys)},

                {ok, Message, UpdatedSession};
            false ->
                {error, invalid_message_header}
        end
    catch
        _:Reason ->
            {error, {decryption_failed, Reason}}
    end.

%% @doc Get the session ID
get_session_id(#{id := Id}) ->
    Id.

%% Private functions

verify_bundle_signature(IdentityKey, SignedPreKeyPublic, Signature) ->
    crypto:verify(IdentityKey, SignedPreKeyPublic, Signature).

calculate_shared_secret(PrivateKey, PublicKey) ->
    crypto:compute_key(ecdh, PublicKey, PrivateKey, prime256v1).

derive_master_secret(PreKeySecret, SignedPreKeySecret, IdentitySecret) ->
    % Combine secrets and derive master secret using HKDF
    CombinedSecret =
        <<PreKeySecret/binary, SignedPreKeySecret/binary, IdentitySecret/binary>>,
    {ok, MasterSecret} = crypto:hmac(<<"SignalProtocol">>, CombinedSecret),
    MasterSecret.

derive_chain_key(MasterSecret) ->
    % Derive chain key using HKDF
    {ok, ChainKey} = crypto:hmac(<<"ChainKey">>, MasterSecret),
    ChainKey.

derive_message_key(ChainKey) ->
    % Derive message key and new chain key using HKDF
    {ok, MessageKey} = crypto:hmac(<<"MessageKey">>, ChainKey),
    {ok, NewChainKey} = crypto:hmac(<<"ChainKey">>, ChainKey),
    {NewChainKey, MessageKey}.

create_message_header(Session) ->
    PreKeyId = maps:get(pre_key_id, Session),
    SignedPreKeyId = maps:get(signed_pre_key_id, Session),
    EphemeralKey = maps:get(ephemeral_key, Session),
    <<PreKeyId:32, SignedPreKeyId:32, EphemeralKey/binary>>.

verify_message_header(Session, Header) ->
    PreKeyId = maps:get(pre_key_id, Session),
    SignedPreKeyId = maps:get(signed_pre_key_id, Session),
    EphemeralKey = maps:get(ephemeral_key, Session),
    <<HeaderPreKeyId:32, HeaderSignedPreKeyId:32, HeaderEphemeralKey/binary>> = Header,
    PreKeyId =:= HeaderPreKeyId
    andalso SignedPreKeyId =:= HeaderSignedPreKeyId
    andalso EphemeralKey =:= HeaderEphemeralKey.

%% Private helper to encode a binary as length-prefixed
encode_bin(Bin) when is_binary(Bin) ->
    <<(byte_size(Bin)):32, Bin/binary>>.
