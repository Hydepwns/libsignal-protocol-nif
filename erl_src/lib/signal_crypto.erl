-module(signal_crypto).

-export([generate_key_pair/0, sign/2, verify/3, encrypt/3, decrypt/3, hmac/2, hash/1,
         random_bytes/1]).

%% @doc Generate a new key pair for asymmetric encryption
%% Uses the NIF's generate_identity_key_pair function
generate_key_pair() ->
    case nif:generate_identity_key_pair() of
        {ok, {PublicKey, PrivateKey}} ->
            {ok, {PublicKey, PrivateKey}};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Sign data with a private key (HMAC-based for now)
%% Uses Erlang's built-in crypto module since NIF doesn't have sign_data
sign(PrivateKey, Data) ->
    try
        % Debug print
        io:format("sign/2: PrivateKey ~p (~p bytes), Data ~p (~p bytes)~n",
                  [PrivateKey, byte_size(PrivateKey), Data, byte_size(Data)]),

        % For now, we'll use a simple HMAC-based signature since we don't have
        % proper asymmetric signing in the NIF. In a real implementation,
        % you'd want proper ECDSA signing.
        Signature = crypto:mac(hmac, sha256, PrivateKey, Data),
        {ok, Signature}
    catch
        _:Reason ->
            {error, Reason}
    end.

%% @doc Verify a signature with a public key (HMAC-based for now)
%% Uses Erlang's built-in crypto module since NIF doesn't have verify_signature
verify(PublicKey, Data, Signature) ->
    try
        % Verify the HMAC-based signature
        ExpectedSignature = crypto:mac(hmac, sha256, PublicKey, Data),
        case crypto:hash_equals(Signature, ExpectedSignature) of
            true ->
                {ok, true};
            false ->
                {error, invalid_signature}
        end
    catch
        _:Reason ->
            {error, Reason}
    end.

%% @doc Encrypt data with a key and IV (AES-256-GCM)
%% Uses Erlang's built-in crypto module since NIF doesn't have encrypt_message/3
encrypt(Key, IV, Data) ->
    try
        % Use AES-256-GCM for authenticated encryption
        {Ciphertext, Tag} =
            crypto:crypto_one_time_aead(aes_256_gcm, Key, IV, Data, <<>>, 16, true),
        Result = <<Ciphertext/binary, Tag/binary>>,
        io:format("signal_crypto:encrypt: Key=~p (~p bytes), IV=~p (~p bytes), Data=~p (~p bytes), Ciphertext=~p (~p bytes), Tag=~p (~p bytes), Result=~p (~p bytes)~n",
                  [Key,
                   byte_size(Key),
                   IV,
                   byte_size(IV),
                   Data,
                   byte_size(Data),
                   Ciphertext,
                   byte_size(Ciphertext),
                   Tag,
                   byte_size(Tag),
                   Result,
                   byte_size(Result)]),
        {ok, Result}
    catch
        _:Reason ->
            {error, Reason}
    end.

%% @doc Decrypt data with a key and IV (AES-256-GCM)
%% Uses Erlang's built-in crypto module since NIF doesn't have decrypt_message/3
decrypt(Key, IV, Ciphertext) ->
    try
        io:format("signal_crypto:decrypt: Key=~p (~p bytes), IV=~p (~p bytes), Ciphertext=~p (~p bytes)~n",
                  [Key, byte_size(Key), IV, byte_size(IV), Ciphertext, byte_size(Ciphertext)]),

        % Extract ciphertext and tag (last 16 bytes are the tag)
        CiphertextLen = byte_size(Ciphertext),
        if CiphertextLen < 16 ->
               {error, invalid_ciphertext};
           true ->
               TagLen = 16,
               DataLen = CiphertextLen - TagLen,
               <<Data:DataLen/binary, Tag:TagLen/binary>> = Ciphertext,
               io:format("signal_crypto:decrypt: extracted Data=~p (~p bytes), Tag=~p (~p bytes)~n",
                         [Data, byte_size(Data), Tag, byte_size(Tag)]),

               % Decrypt AES-256-GCM ciphertext
               Plaintext =
                   crypto:crypto_one_time_aead(aes_256_gcm, Key, IV, Data, <<>>, Tag, false),
               io:format("signal_crypto:decrypt: Plaintext=~p (~p bytes)~n",
                         [Plaintext, byte_size(Plaintext)]),
               {ok, Plaintext}
        end
    catch
        _:Reason ->
            {error, Reason}
    end.

%% @doc Generate an HMAC of data with a key
%% Uses Erlang's built-in crypto module since NIF doesn't have hmac_sha256
hmac(Key, Data) ->
    try
        Mac = crypto:mac(hmac, sha256, Key, Data),
        {ok, Mac}
    catch
        _:Reason ->
            {error, Reason}
    end.

%% @doc Generate a SHA-256 hash of data
%% Uses Erlang's built-in crypto module since NIF doesn't have sha256
hash(Data) ->
    try
        Hash = crypto:hash(sha256, Data),
        {ok, Hash}
    catch
        _:Reason ->
            {error, Reason}
    end.

%% @doc Generate random bytes
%% Uses Erlang's built-in crypto module since NIF doesn't have random_bytes
random_bytes(N) ->
    try
        Bytes = crypto:strong_rand_bytes(N),
        {ok, Bytes}
    catch
        _:Reason ->
            {error, Reason}
    end.
