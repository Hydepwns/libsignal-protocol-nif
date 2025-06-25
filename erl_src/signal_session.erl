-module(signal_session).

-export([new/2, process_pre_key_bundle/2, encrypt/2, decrypt/2, get_session_id/1]).

-include_lib("erl_src/include/signal_types.hrl").

%% @doc Create a new session
new(LocalIdentityKey, RemoteIdentityKey) ->
    % Generate deterministic session ID based on the input keys
    SessionId = generate_deterministic_session_id(LocalIdentityKey, RemoteIdentityKey),
    #{id => SessionId,
      local_identity_key => LocalIdentityKey,
      remote_identity_key => RemoteIdentityKey,
      pre_key_id => undefined,
      signed_pre_key_id => undefined,
      ephemeral_key => undefined,
      chain_key => undefined,
      message_keys => #{},
      message_counter => 0}.

%% @doc Generate a deterministic session ID based on the input keys
generate_deterministic_session_id(LocalIdentityKey, RemoteIdentityKey) ->
    % Create a deterministic hash of the keys to ensure same keys = same session ID
    KeyData = <<LocalIdentityKey/binary, RemoteIdentityKey/binary>>,
    {ok, Hash} = signal_crypto:hash(KeyData),
    % Use the first 32 bytes of the hash as the session ID
    <<SessionId:32/binary, _/binary>> = Hash,
    SessionId.

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

            io:format("process_pre_key_bundle: calling nif:process_pre_key_bundle with BundleBinary=~p (~p bytes)~n",
                      [BundleBinary, byte_size(BundleBinary)]),
            case nif:process_pre_key_bundle(DummySession, BundleBinary) of
                {ok, {RegId, DevId, PKId, PKPub, SPKId, SPKPub, IdKey, EphKey, ChainKey}} ->
                    io:format("process_pre_key_bundle: NIF returned RegId=~p, DevId=~p, PKId=~p, SPKId=~p, EphKey=~p (~p bytes), ChainKey=~p (~p bytes)~n",
                              [RegId,
                               DevId,
                               PKId,
                               SPKId,
                               EphKey,
                               byte_size(EphKey),
                               ChainKey,
                               byte_size(ChainKey)]),
                    % Convert the NIF response to a session record
                    UpdatedSession =
                        Session#{pre_key_id => PKId,
                                 signed_pre_key_id => SPKId,
                                 ephemeral_key => EphKey,
                                 chain_key => ChainKey},
                    io:format("process_pre_key_bundle: UpdatedSession=~p~n", [UpdatedSession]),
                    {ok, UpdatedSession};
                {error, Reason} ->
                    io:format("process_pre_key_bundle: NIF error ~p~n", [Reason]),
                    {error, Reason}
            end;
        _ ->
            io:format("process_pre_key_bundle: signature verification failed~n"),
            {error, invalid_signature}
    end.

%% @doc Encrypt a message using the session
encrypt(Session, Message) ->
    try
        io:format("signal_session:encrypt: Session=~p, Message=~p (~p bytes)~n",
                  [Session, Message, byte_size(Message)]),
        ChainKey = maps:get(chain_key, Session),
        MessageKeys = maps:get(message_keys, Session, #{}),
        MessageCounter = maps:get(message_counter, Session, 0),
        io:format("signal_session:encrypt: ChainKey=~p (~p bytes), MessageKeys=~p, MessageCounter=~p~n",
                  [ChainKey, byte_size(ChainKey), MessageKeys, MessageCounter]),

        % Generate new message key
        {NewChainKey, MessageKey} = derive_message_key(ChainKey),
        io:format("signal_session:encrypt: NewChainKey=~p (~p bytes), MessageKey=~p (~p bytes)~n",
                  [NewChainKey, byte_size(NewChainKey), MessageKey, byte_size(MessageKey)]),

        % Encrypt the message
        {ok, IV} = signal_crypto:random_bytes(12),

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

        {ok, CiphertextWithTag} = signal_crypto:encrypt(MessageKey, IV, Message),
        io:format("signal_session:encrypt: CiphertextWithTag=~p (~p bytes)~n",
                  [CiphertextWithTag, byte_size(CiphertextWithTag)]),

        % Create message header
        Header = create_message_header(Session),
        io:format("signal_session:encrypt: Header=~p (~p bytes)~n", [Header, byte_size(Header)]),

        % Update session
        UpdatedSession =
            Session#{chain_key := NewChainKey,
                     message_keys := maps:put(MessageCounter, MessageKey, MessageKeys),
                     message_counter := MessageCounter + 1},
        io:format("signal_session:encrypt: UpdatedSession message_keys=~p, message_counter=~p~n",
                  [maps:get(message_keys, UpdatedSession),
                   maps:get(message_counter, UpdatedSession)]),

        % Combine header, IV, and ciphertext+tag
        EncryptedMessage = <<Header/binary, IV/binary, CiphertextWithTag/binary>>,
        io:format("signal_session:encrypt: EncryptedMessage=~p (~p bytes)~n",
                  [EncryptedMessage, byte_size(EncryptedMessage)]),

        {ok, EncryptedMessage, UpdatedSession}
    catch
        _:Reason ->
            io:format("signal_session:encrypt: ERROR ~p~n", [Reason]),
            {error, {encryption_failed, Reason}}
    end.

%% @doc Decrypt a message using the session
decrypt(Session, Ciphertext) ->
    try
        % Calculate header size based on ephemeral key size
        EphemeralKey = maps:get(ephemeral_key, Session),
        HeaderSize =
            8
            + byte_size(EphemeralKey), % 4 bytes for PreKeyId + 4 bytes for SignedPreKeyId + ephemeral key size

        % Extract message components
        <<Header:HeaderSize/binary, IV:12/binary, CiphertextWithTag/binary>> = Ciphertext,

        % Verify message header
        case verify_message_header(Session, Header) of
            true ->
                % Get the message counter to find the correct message key
                % For decryption, we need to use the counter that was used during encryption
                % Since the encrypt function increments the counter after storing the key,
                % we need to use (counter - 1) to get the key that was used
                MessageCounter = maps:get(message_counter, Session, 0),
                MessageKeys = maps:get(message_keys, Session, #{}),
                io:format("signal_session:decrypt: MessageCounter=~p, MessageKeys=~p~n",
                          [MessageCounter, MessageKeys]),

                % Get the message key that was used for encryption
                case maps:get(MessageCounter - 1, MessageKeys, undefined) of
                    undefined ->
                        io:format("signal_session:decrypt: message key not found at counter ~p~n",
                                  [MessageCounter - 1]),
                        {error, message_key_not_found};
                    MessageKey ->
                        io:format("signal_session:decrypt: using MessageKey=~p (~p bytes), IV=~p (~p bytes), CiphertextWithTag=~p (~p bytes)~n",
                                  [MessageKey,
                                   byte_size(MessageKey),
                                   IV,
                                   byte_size(IV),
                                   CiphertextWithTag,
                                   byte_size(CiphertextWithTag)]),
                        % Decrypt the message (CiphertextWithTag already includes the tag)
                        {ok, Message} = signal_crypto:decrypt(MessageKey, IV, CiphertextWithTag),

                        % Update session - remove the used message key and increment counter
                        UpdatedMessageKeys = maps:remove(MessageCounter - 1, MessageKeys),
                        UpdatedSession =
                            Session#{message_keys := UpdatedMessageKeys,
                                     message_counter := MessageCounter + 1},

                        {ok, Message, UpdatedSession}
                end;
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
    signal_crypto:verify(IdentityKey, SignedPreKeyPublic, Signature).

calculate_shared_secret(PrivateKey, PublicKey) ->
    signal_crypto:compute_key(ecdh, PublicKey, PrivateKey, prime256v1).

derive_master_secret(PreKeySecret, SignedPreKeySecret, IdentitySecret) ->
    % Combine secrets and derive master secret using HKDF
    CombinedSecret =
        <<PreKeySecret/binary, SignedPreKeySecret/binary, IdentitySecret/binary>>,
    {ok, MasterSecret} = signal_crypto:hmac(<<"SignalProtocol">>, CombinedSecret),
    MasterSecret.

derive_chain_key(MasterSecret) ->
    % Derive chain key using HKDF
    {ok, ChainKey} = signal_crypto:hmac(<<"ChainKey">>, MasterSecret),
    ChainKey.

derive_message_key(ChainKey) ->
    % Derive message key and new chain key using HKDF
    {ok, MessageKey} = signal_crypto:hmac(<<"MessageKey">>, ChainKey),
    {ok, NewChainKey} = signal_crypto:hmac(<<"ChainKey">>, ChainKey),
    {NewChainKey, MessageKey}.

create_message_header(Session) ->
    PreKeyId = maps:get(pre_key_id, Session),
    SignedPreKeyId = maps:get(signed_pre_key_id, Session),
    EphemeralKey = maps:get(ephemeral_key, Session),
    Header = <<PreKeyId:32, SignedPreKeyId:32, EphemeralKey/binary>>,
    io:format("create_message_header: PreKeyId=~p, SignedPreKeyId=~p, EphemeralKey=~p (~p bytes), Header=~p (~p bytes)~n",
              [PreKeyId,
               SignedPreKeyId,
               EphemeralKey,
               byte_size(EphemeralKey),
               Header,
               byte_size(Header)]),
    Header.

verify_message_header(Session, Header) ->
    PreKeyId = maps:get(pre_key_id, Session),
    SignedPreKeyId = maps:get(signed_pre_key_id, Session),
    EphemeralKey = maps:get(ephemeral_key, Session),
    io:format("verify_message_header: PreKeyId=~p, SignedPreKeyId=~p, EphemeralKey=~p (~p bytes), Header=~p (~p bytes)~n",
              [PreKeyId,
               SignedPreKeyId,
               EphemeralKey,
               byte_size(EphemeralKey),
               Header,
               byte_size(Header)]),
    <<HeaderPreKeyId:32, HeaderSignedPreKeyId:32, HeaderEphemeralKey/binary>> = Header,
    Result =
        PreKeyId =:= HeaderPreKeyId
        andalso SignedPreKeyId =:= HeaderSignedPreKeyId
        andalso EphemeralKey =:= HeaderEphemeralKey,
    io:format("verify_message_header: HeaderPreKeyId=~p, HeaderSignedPreKeyId=~p, HeaderEphemeralKey=~p (~p bytes), Result=~p~n",
              [HeaderPreKeyId,
               HeaderSignedPreKeyId,
               HeaderEphemeralKey,
               byte_size(HeaderEphemeralKey),
               Result]),
    Result.

%% Private helper to encode a binary as length-prefixed
encode_bin(Bin) when is_binary(Bin) ->
    <<(byte_size(Bin)):32, Bin/binary>>.
