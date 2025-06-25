-module(crypto_wrapper_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("eunit/include/eunit.hrl").

-compile(export_all).

all() ->
    [test_generate_key_pair,
     test_sign_verify,
     test_encrypt_decrypt,
     test_hmac,
     test_hash,
     test_random_bytes,
     test_crypto_error_handling,
     test_crypto_concurrent_operations,
     test_crypto_large_data,
     test_crypto_edge_cases,
     test_crypto_performance].

init_per_suite(Config) ->
    io:format("crypto_wrapper_SUITE: init_per_suite starting~n", []),
    application:ensure_all_started(nif),
    case nif:init() of
        ok ->
            io:format("NIF initialized successfully~n"),
            Config;
        {error, Reason} ->
            io:format("Failed to initialize NIF: ~p~n", [Reason]),
            {skip, "NIF initialization failed"}
    end.

end_per_suite(_Config) ->
    ok.

test_generate_key_pair(_Config) ->
    % Test basic key pair generation
    {ok, {PublicKey, PrivateKey}} = signal_crypto:generate_key_pair(),
    ?assert(is_binary(PublicKey)),
    ?assert(is_binary(PrivateKey)),
    ?assertEqual(32, byte_size(PublicKey)),
    ?assertEqual(32, byte_size(PrivateKey)),

    % Test that keys are different
    ?assertNotEqual(PublicKey, PrivateKey),

    % Test multiple generations produce different keys
    {ok, {PublicKey2, PrivateKey2}} = signal_crypto:generate_key_pair(),
    ?assertNotEqual(PublicKey, PublicKey2),
    ?assertNotEqual(PrivateKey, PrivateKey2).

test_sign_verify(_Config) ->
    % Generate key pair
    {ok, {PublicKey, PrivateKey}} = signal_crypto:generate_key_pair(),

    % Test data to sign
    TestData =
        [<<"Hello, World!">>,
         <<"Short">>,
         binary:copy(<<"A">>, 1000),
         crypto:strong_rand_bytes(5000)],

    [begin
         % Sign data with private key (HMAC-based)
         {ok, Signature} = signal_crypto:sign(PrivateKey, Data),
         ?assert(is_binary(Signature)),
         ?assert(byte_size(Signature) > 0),

         % Verify signature with private key (HMAC-based, same key)
         {ok, true} = signal_crypto:verify(PrivateKey, Data, Signature),

         % Test invalid signature
         InvalidSignature = crypto:strong_rand_bytes(byte_size(Signature)),
         {error, invalid_signature} = signal_crypto:verify(PrivateKey, Data, InvalidSignature)
     end
     || Data <- TestData].

test_encrypt_decrypt(_Config) ->
    % Generate keys and IVs
    Keys = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 5)],
    IVs = [crypto:strong_rand_bytes(12) || _ <- lists:seq(1, 5)],

    % Test data to encrypt
    TestData =
        [<<"Hello, World!">>,
         <<"Short">>,
         binary:copy(<<"A">>, 1000),
         crypto:strong_rand_bytes(5000),
         binary:copy(<<"B">>, 10000)],

    [begin
         [begin
              % Encrypt data
              {ok, Encrypted} = signal_crypto:encrypt(Key, IV, Data),
              ?assert(is_binary(Encrypted)),
              ?assert(byte_size(Encrypted) > byte_size(Data)),

              % Decrypt data
              {ok, Decrypted} = signal_crypto:decrypt(Key, IV, Encrypted),
              ?assertEqual(Data, Decrypted),

              % Test with wrong key
              WrongKey = crypto:strong_rand_bytes(32),
              {error, _} = signal_crypto:decrypt(WrongKey, IV, Encrypted),

              % Test with wrong IV
              WrongIV = crypto:strong_rand_bytes(12),
              {error, _} = signal_crypto:decrypt(Key, WrongIV, Encrypted)
          end
          || {Key, IV} <- lists:zip(Keys, IVs)]
     end
     || Data <- TestData].

test_hmac(_Config) ->
    % Generate keys
    Keys = [crypto:strong_rand_bytes(32) || _ <- lists:seq(1, 5)],

    % Test data
    TestData =
        [<<"Hello, World!">>,
         <<"Short">>,
         binary:copy(<<"A">>, 1000),
         crypto:strong_rand_bytes(5000)],

    [begin
         [begin
              % Generate HMAC
              {ok, Hmac} = signal_crypto:hmac(Key, Data),
              ?assert(is_binary(Hmac)),
              ?assertEqual(32, byte_size(Hmac)), % SHA-256 HMAC is 32 bytes

              % Verify HMAC is deterministic
              {ok, Hmac2} = signal_crypto:hmac(Key, Data),
              ?assertEqual(Hmac, Hmac2)
          end
          || Key <- Keys]
     end
     || Data <- TestData].

test_hash(_Config) ->
    % Test data
    TestData =
        [<<"Hello, World!">>,
         <<"Short">>,
         binary:copy(<<"A">>, 1000),
         crypto:strong_rand_bytes(5000),
         <<>>],  % Empty data

    [begin
         % Generate hash
         {ok, Hash} = signal_crypto:hash(Data),
         ?assert(is_binary(Hash)),
         ?assertEqual(32, byte_size(Hash)), % SHA-256 is 32 bytes

         % Verify hash is deterministic
         {ok, Hash2} = signal_crypto:hash(Data),
         ?assertEqual(Hash, Hash2)
     end
     || Data <- TestData].

test_random_bytes(_Config) ->
    % Test different sizes
    Sizes = [1, 16, 32, 64, 128, 256, 1024],

    [begin
         {ok, RandomBytes} = signal_crypto:random_bytes(Size),
         ?assert(is_binary(RandomBytes)),
         ?assertEqual(Size, byte_size(RandomBytes))
     end
     || Size <- Sizes],

    % Test that random bytes are actually random
    {ok, Random1} = signal_crypto:random_bytes(1000),
    {ok, Random2} = signal_crypto:random_bytes(1000),
    ?assertNotEqual(Random1, Random2).

test_crypto_error_handling(_Config) ->
    % Test invalid inputs for sign - empty key and short key should work (HMAC allows empty key)
    {ok, _} = signal_crypto:sign(<<>>, <<"data">>),
    {ok, _} = signal_crypto:sign(<<"short">>, <<"data">>),

    % Test invalid inputs for verify - both empty key and short key should fail
    ?assertMatch({error, badarg}, signal_crypto:verify(<<>>, <<"data">>, <<"sig">>)),
    ?assertMatch({error, badarg}, signal_crypto:verify(<<"short">>, <<"data">>, <<"sig">>)),

    % Test invalid inputs for encrypt - should fail with wrong key size
    ?assertMatch({error, _}, signal_crypto:encrypt(<<>>, <<"iv">>, <<"data">>)),
    ?assertMatch({error, _}, signal_crypto:encrypt(<<"short">>, <<"iv">>, <<"data">>)),
    ?assertMatch({error, _},
                 signal_crypto:encrypt(
                     crypto:strong_rand_bytes(32), <<>>, <<"data">>)),

    % Test invalid inputs for decrypt - should fail with wrong key size
    ?assertMatch({error, _}, signal_crypto:decrypt(<<>>, <<"iv">>, <<"data">>)),
    ?assertMatch({error, _}, signal_crypto:decrypt(<<"short">>, <<"iv">>, <<"data">>)),
    ?assertMatch({error, _},
                 signal_crypto:decrypt(
                     crypto:strong_rand_bytes(32), <<>>, <<"data">>)),
    ?assertMatch({error, _},
                 signal_crypto:decrypt(
                     crypto:strong_rand_bytes(32), crypto:strong_rand_bytes(12), <<>>)),

    % Test invalid inputs for hmac - empty key should work
    {ok, _} = signal_crypto:hmac(<<>>, <<"data">>),

    % Test invalid inputs for hash - should fail with non-binary
    ?assertMatch({error, badarg}, signal_crypto:hash(not_binary)),

    % Test invalid inputs for random_bytes - zero size returns empty binary, negative size fails
    {ok, <<>>} = signal_crypto:random_bytes(0),
    ?assertMatch({error, badarg}, signal_crypto:random_bytes(-1)).

test_crypto_concurrent_operations(_Config) ->
    % Test concurrent key generation
    NumProcesses = 10,
    NumKeysPerProcess = 10,

    Pids =
        [spawn(fun() ->
                  Keys =
                      [begin
                           {ok, {PublicKey, PrivateKey}} = signal_crypto:generate_key_pair(),
                           {PublicKey, PrivateKey}
                       end
                       || _ <- lists:seq(1, NumKeysPerProcess)],
                  exit({keys, Keys})
               end)
         || _ <- lists:seq(1, NumProcesses)],

    Results =
        [receive
             {'EXIT', Pid, {keys, Keys}} ->
                 Keys
         end
         || Pid <- Pids],

    % Verify all keys are unique
    AllKeys = lists:flatten(Results),
    PublicKeys = [PublicKey || {PublicKey, _} <- AllKeys],
    UniquePublicKeys = sets:from_list(PublicKeys),
    ?assertEqual(length(PublicKeys), sets:size(UniquePublicKeys)),

    % Test concurrent encryption/decryption
    {ok, {PublicKey, PrivateKey}} = signal_crypto:generate_key_pair(),
    Key = crypto:strong_rand_bytes(32),
    IV = crypto:strong_rand_bytes(12),
    TestMessage = <<"Concurrent test message">>,

    Pids2 =
        [spawn(fun() ->
                  {ok, Encrypted} = signal_crypto:encrypt(Key, IV, TestMessage),
                  {ok, Decrypted} = signal_crypto:decrypt(Key, IV, Encrypted),
                  exit({result, Decrypted})
               end)
         || _ <- lists:seq(1, 20)],

    Results2 =
        [receive
             {'EXIT', Pid, {result, Decrypted}} ->
                 Decrypted
         end
         || Pid <- Pids2],

    % Verify all results are correct
    [?assertEqual(TestMessage, Result) || Result <- Results2].

test_crypto_large_data(_Config) ->
    % Test with large data
    LargeDataSizes = [100000, 500000, 1000000], % 100KB, 500KB, 1MB

    [begin
         LargeData = crypto:strong_rand_bytes(Size),
         Key = crypto:strong_rand_bytes(32),
         IV = crypto:strong_rand_bytes(12),

         % Test encryption/decryption
         {ok, Encrypted} = signal_crypto:encrypt(Key, IV, LargeData),
         {ok, Decrypted} = signal_crypto:decrypt(Key, IV, Encrypted),
         ?assertEqual(LargeData, Decrypted),

         % Test HMAC
         {ok, Hmac} = signal_crypto:hmac(Key, LargeData),
         ?assertEqual(32, byte_size(Hmac)),

         % Test hash
         {ok, Hash} = signal_crypto:hash(LargeData),
         ?assertEqual(32, byte_size(Hash))
     end
     || Size <- LargeDataSizes].

test_crypto_edge_cases(_Config) ->
    % Test edge cases
    {ok, {PublicKey, PrivateKey}} = signal_crypto:generate_key_pair(),
    Key = crypto:strong_rand_bytes(32),
    IV = crypto:strong_rand_bytes(12),

    % Test empty data
    EmptyData = <<>>,
    {ok, EncryptedEmpty} = signal_crypto:encrypt(Key, IV, EmptyData),
    {ok, DecryptedEmpty} = signal_crypto:decrypt(Key, IV, EncryptedEmpty),
    ?assertEqual(EmptyData, DecryptedEmpty),

    {ok, HmacEmpty} = signal_crypto:hmac(Key, EmptyData),
    ?assertEqual(32, byte_size(HmacEmpty)),

    {ok, HashEmpty} = signal_crypto:hash(EmptyData),
    ?assertEqual(32, byte_size(HashEmpty)),

    % Test single byte data
    SingleByte = <<1>>,
    {ok, EncryptedSingle} = signal_crypto:encrypt(Key, IV, SingleByte),
    {ok, DecryptedSingle} = signal_crypto:decrypt(Key, IV, EncryptedSingle),
    ?assertEqual(SingleByte, DecryptedSingle),

    % Test very large random bytes
    {ok, LargeRandom} = signal_crypto:random_bytes(100000),
    ?assertEqual(100000, byte_size(LargeRandom)).

test_crypto_performance(_Config) ->
    % Simple performance test
    NumOperations = 1000,
    Key = crypto:strong_rand_bytes(32),
    IV = crypto:strong_rand_bytes(12),
    TestData = crypto:strong_rand_bytes(1024),

    % Test encryption performance
    StartTime = os:system_time(microsecond),
    [begin {ok, _} = signal_crypto:encrypt(Key, IV, TestData) end
     || _ <- lists:seq(1, NumOperations)],
    EndTime = os:system_time(microsecond),
    EncryptionTime = (EndTime - StartTime) / 1000000.0,

    io:format("Encrypted ~p messages in ~.3f seconds (~.0f ops/sec)~n",
              [NumOperations, EncryptionTime, NumOperations / EncryptionTime]),

    % Test hash performance
    StartTime2 = os:system_time(microsecond),
    [begin {ok, _} = signal_crypto:hash(TestData) end || _ <- lists:seq(1, NumOperations)],
    EndTime2 = os:system_time(microsecond),
    HashTime = (EndTime2 - StartTime2) / 1000000.0,

    io:format("Hashed ~p messages in ~.3f seconds (~.0f ops/sec)~n",
              [NumOperations, HashTime, NumOperations / HashTime]).
