-module(signal_session).

-export([
    new/2,
    process_pre_key_bundle/2,
    encrypt/2,
    decrypt/2,
    get_session_id/1
]).

-include("signal_types.hrl").

%% @doc Create a new session
new(LocalIdentityKey, RemoteIdentityKey) ->
    SessionId = signal_crypto:random_bytes(32),
    #session{
        id = SessionId,
        local_identity_key = LocalIdentityKey,
        remote_identity_key = RemoteIdentityKey
    }.

%% @doc Process a pre-key bundle to establish a session
process_pre_key_bundle(Session, Bundle) ->
    {RegistrationId, DeviceId, PreKey, SignedPreKey, IdentityKey} = Bundle,
    case signal_nif:process_pre_key_bundle(Session, Bundle) of
        {ok, UpdatedSession} ->
            % Convert the session record to a map
            MapSession = #{
                id => UpdatedSession#session.id,
                local_identity_key => UpdatedSession#session.local_identity_key,
                remote_identity_key => UpdatedSession#session.remote_identity_key,
                pre_key_id => UpdatedSession#session.pre_key_id,
                signed_pre_key_id => UpdatedSession#session.signed_pre_key_id,
                ephemeral_key => UpdatedSession#session.ephemeral_key,
                chain_key => UpdatedSession#session.chain_key,
                message_keys => UpdatedSession#session.message_keys
            },
            {ok, MapSession};
        Error ->
            Error
    end.

%% @doc Encrypt a message using the session
encrypt(Session, Message) ->
    try
        #session{
            chain_key = ChainKey,
            message_keys = MessageKeys
        } = Session,

        % Generate new message key
        {NewChainKey, MessageKey} = derive_message_key(ChainKey),

        % Encrypt the message
        IV = signal_crypto:random_bytes(16),
        Ciphertext = signal_crypto:encrypt(MessageKey, IV, Message),

        % Create message header
        Header = create_message_header(Session),

        % Update session
        UpdatedSession = Session#session{
            chain_key = NewChainKey,
            message_keys = maps:put(MessageKey, true, MessageKeys)
        },

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
        <<Header:32/binary, IV:16/binary, EncryptedData/binary>> = Ciphertext,

        % Verify message header
        case verify_message_header(Session, Header) of
            true ->
                % Derive message key
                {NewChainKey, MessageKey} = derive_message_key(Session#session.chain_key),

                % Decrypt the message
                Message = signal_crypto:decrypt(MessageKey, IV, EncryptedData),

                % Update session
                UpdatedSession = Session#session{
                    chain_key = NewChainKey,
                    message_keys = maps:put(MessageKey, true, Session#session.message_keys)
                },

                {ok, Message, UpdatedSession};
            false ->
                {error, invalid_message_header}
        end
    catch
        _:Reason ->
            {error, {decryption_failed, Reason}}
    end.

%% @doc Get the session ID
get_session_id(#session{id = Id}) ->
    Id.

%% Private functions

verify_bundle_signature(IdentityKey, SignedPreKeyPublic, Signature) ->
    signal_crypto:verify(IdentityKey, SignedPreKeyPublic, Signature).

calculate_shared_secret(PrivateKey, PublicKey) ->
    signal_crypto:compute_key(ecdh, PublicKey, PrivateKey, prime256v1).

derive_master_secret(PreKeySecret, SignedPreKeySecret, IdentitySecret) ->
    % Combine secrets and derive master secret using HKDF
    CombinedSecret = <<PreKeySecret/binary, SignedPreKeySecret/binary, IdentitySecret/binary>>,
    signal_crypto:mac(hmac, sha256, <<"SignalProtocol">>, CombinedSecret).

derive_chain_key(MasterSecret) ->
    % Derive chain key using HKDF
    signal_crypto:mac(hmac, sha256, <<"ChainKey">>, MasterSecret).

derive_message_key(ChainKey) ->
    % Derive message key and new chain key using HKDF
    MessageKey = signal_crypto:mac(hmac, sha256, <<"MessageKey">>, ChainKey),
    NewChainKey = signal_crypto:mac(hmac, sha256, <<"ChainKey">>, ChainKey),
    {NewChainKey, MessageKey}.

create_message_header(Session) ->
    #session{
        pre_key_id = PreKeyId,
        signed_pre_key_id = SignedPreKeyId,
        ephemeral_key = EphemeralKey
    } = Session,
    <<PreKeyId:32, SignedPreKeyId:32, EphemeralKey/binary>>.

verify_message_header(Session, Header) ->
    #session{
        pre_key_id = PreKeyId,
        signed_pre_key_id = SignedPreKeyId,
        ephemeral_key = EphemeralKey
    } = Session,
    <<HeaderPreKeyId:32, HeaderSignedPreKeyId:32, HeaderEphemeralKey/binary>> = Header,
    PreKeyId =:= HeaderPreKeyId andalso
    SignedPreKeyId =:= HeaderSignedPreKeyId andalso
    EphemeralKey =:= HeaderEphemeralKey. 