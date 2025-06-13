-module(signal_crypto).

-export([
    generate_key_pair/0,
    sign/2,
    verify/3,
    encrypt/3,
    decrypt/3,
    hmac/2,
    hash/1,
    random_bytes/1
]).

%% @doc Generate a new key pair for asymmetric encryption
generate_key_pair() ->
    case signal_nif:generate_identity_key_pair() of
        {ok, {PublicKey, Signature}} ->
            {ok, {PublicKey, Signature}};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Sign data with a private key
sign(PrivateKey, Data) ->
    case signal_nif:sign_data(PrivateKey, Data) of
        {ok, Signature} ->
            {ok, Signature};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Verify a signature with a public key
verify(PublicKey, Data, Signature) ->
    case signal_nif:verify_signature(PublicKey, Data, Signature) of
        {ok, true} ->
            {ok, true};
        {ok, false} ->
            {error, invalid_signature};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Encrypt data with a key and IV
encrypt(Key, IV, Data) ->
    case signal_nif:encrypt_message(Key, IV, Data) of
        {ok, Ciphertext} ->
            {ok, Ciphertext};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Decrypt data with a key and IV
decrypt(Key, IV, Ciphertext) ->
    case signal_nif:decrypt_message(Key, IV, Ciphertext) of
        {ok, Plaintext} ->
            {ok, Plaintext};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Generate an HMAC of data with a key
hmac(Key, Data) ->
    case signal_nif:hmac_sha256(Key, Data) of
        {ok, Mac} ->
            {ok, Mac};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Generate a SHA-256 hash of data
hash(Data) ->
    case signal_nif:sha256(Data) of
        {ok, Hash} ->
            {ok, Hash};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Generate random bytes
random_bytes(N) ->
    case signal_nif:random_bytes(N) of
        {ok, Bytes} ->
            {ok, Bytes};
        {error, Reason} ->
            {error, Reason}
    end. 