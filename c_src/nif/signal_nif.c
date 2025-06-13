#include "signal_nif.h"
#include <erl_nif.h>
#include <string.h>

// Resource type definitions
ErlNifResourceType* signal_store_resource_type;
ErlNifResourceType* signal_session_resource_type;

// Helper functions
ERL_NIF_TERM make_error(ErlNifEnv* env, const char* error) {
    return enif_make_tuple2(env,
                           enif_make_atom(env, "error"),
                           enif_make_string(env, error, ERL_NIF_LATIN1));
}

ERL_NIF_TERM make_ok(ErlNifEnv* env, ERL_NIF_TERM value) {
    return enif_make_tuple2(env,
                           enif_make_atom(env, "ok"),
                           value);
}

ERL_NIF_TERM make_binary(ErlNifEnv* env, const void* data, size_t size) {
    ErlNifBinary bin;
    if (!enif_alloc_binary(size, &bin)) {
        return make_error(env, "failed to allocate binary");
    }
    memcpy(bin.data, data, size);
    return enif_make_binary(env, &bin);
}

int get_binary(ErlNifEnv* env, ERL_NIF_TERM term, ErlNifBinary* bin) {
    return enif_inspect_binary(env, term, bin);
}

// Resource cleanup functions
static void signal_store_dtor(ErlNifEnv* env, void* obj) {
    signal_store_resource_t* resource = (signal_store_resource_t*)obj;
    if (resource->store) {
        signal_protocol_store_destroy(resource->store);
    }
}

static void signal_session_dtor(ErlNifEnv* env, void* obj) {
    signal_session_resource_t* resource = (signal_session_resource_t*)obj;
    if (resource->session) {
        signal_session_destroy(resource->session);
    }
}

// NIF function implementations
ERL_NIF_TERM signal_nif_generate_identity_key_pair(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 0) {
        return enif_make_badarg(env);
    }

    signal_identity_key_t identity_key;
    signal_error_t result = signal_generate_identity_key_pair(&identity_key);
    if (result != SIGNAL_OK) {
        return make_error(env, "failed to generate identity key pair");
    }

    ERL_NIF_TERM public_key = make_binary(env, identity_key.key.key, SIGNAL_IDENTITY_KEY_SIZE);
    ERL_NIF_TERM signature = make_binary(env, identity_key.signature, 64);

    return make_ok(env, enif_make_tuple2(env, public_key, signature));
}

ERL_NIF_TERM signal_nif_generate_pre_key(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 1) {
        return enif_make_badarg(env);
    }

    uint32_t key_id;
    if (!enif_get_uint(env, argv[0], &key_id)) {
        return enif_make_badarg(env);
    }

    signal_pre_key_t pre_key;
    signal_error_t result = signal_generate_pre_key(&pre_key, key_id);
    if (result != SIGNAL_OK) {
        return make_error(env, "failed to generate pre key");
    }

    ERL_NIF_TERM key_id_term = enif_make_uint(env, pre_key.key_id);
    ERL_NIF_TERM public_key = make_binary(env, pre_key.key.key, SIGNAL_PRE_KEY_SIZE);

    return make_ok(env, enif_make_tuple2(env, key_id_term, public_key));
}

ERL_NIF_TERM signal_nif_generate_signed_pre_key(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 2) {
        return enif_make_badarg(env);
    }

    ErlNifBinary identity_key_bin;
    if (!get_binary(env, argv[0], &identity_key_bin) ||
        identity_key_bin.size != SIGNAL_IDENTITY_KEY_SIZE) {
        return enif_make_badarg(env);
    }

    uint32_t key_id;
    if (!enif_get_uint(env, argv[1], &key_id)) {
        return enif_make_badarg(env);
    }

    signal_identity_key_t identity_key;
    memcpy(identity_key.key.key, identity_key_bin.data, SIGNAL_IDENTITY_KEY_SIZE);

    signal_signed_pre_key_t signed_pre_key;
    signal_error_t result = signal_generate_signed_pre_key(&signed_pre_key, &identity_key, key_id);
    if (result != SIGNAL_OK) {
        return make_error(env, "failed to generate signed pre key");
    }

    ERL_NIF_TERM key_id_term = enif_make_uint(env, signed_pre_key.key_id);
    ERL_NIF_TERM public_key = make_binary(env, signed_pre_key.key.key, SIGNAL_SIGNED_PRE_KEY_SIZE);
    ERL_NIF_TERM signature = make_binary(env, signed_pre_key.signature, 64);

    return make_ok(env, enif_make_tuple3(env, key_id_term, public_key, signature));
}

ERL_NIF_TERM signal_nif_create_session(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 3) {
        return enif_make_badarg(env);
    }

    ErlNifBinary local_identity_key_bin, remote_identity_key_bin;
    if (!get_binary(env, argv[0], &local_identity_key_bin) ||
        local_identity_key_bin.size != SIGNAL_IDENTITY_KEY_SIZE ||
        !get_binary(env, argv[1], &remote_identity_key_bin) ||
        remote_identity_key_bin.size != SIGNAL_IDENTITY_KEY_SIZE) {
        return enif_make_badarg(env);
    }

    signal_identity_key_t local_identity_key, remote_identity_key;
    memcpy(local_identity_key.key.key, local_identity_key_bin.data, SIGNAL_IDENTITY_KEY_SIZE);
    memcpy(remote_identity_key.key.key, remote_identity_key_bin.data, SIGNAL_IDENTITY_KEY_SIZE);

    signal_protocol_store_t* store;
    signal_error_t result = signal_protocol_store_create(&store);
    if (result != SIGNAL_OK) {
        return make_error(env, "failed to create protocol store");
    }

    signal_session_state_t* session;
    result = signal_session_create(&session, store, &local_identity_key, &remote_identity_key);
    if (result != SIGNAL_OK) {
        signal_protocol_store_destroy(store);
        return make_error(env, "failed to create session");
    }

    signal_session_resource_t* resource = enif_alloc_resource(signal_session_resource_type,
                                                            sizeof(signal_session_resource_t));
    if (!resource) {
        signal_session_destroy(session);
        signal_protocol_store_destroy(store);
        return make_error(env, "failed to allocate resource");
    }

    resource->session = session;
    ERL_NIF_TERM resource_term = enif_make_resource(env, resource);
    enif_release_resource(resource);

    return make_ok(env, resource_term);
}

ERL_NIF_TERM signal_nif_process_pre_key_bundle(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 2) {
        return enif_make_badarg(env);
    }

    signal_session_resource_t* resource;
    if (!enif_get_resource(env, argv[0], signal_session_resource_type, (void**)&resource)) {
        return enif_make_badarg(env);
    }

    ErlNifBinary bundle_bin;
    if (!get_binary(env, argv[1], &bundle_bin)) {
        return enif_make_badarg(env);
    }

    signal_pre_key_bundle_t* bundle = (signal_pre_key_bundle_t*)bundle_bin.data;
    signal_error_t result = signal_process_pre_key_bundle(resource->session, bundle);
    if (result != SIGNAL_OK) {
        return make_error(env, "failed to process pre key bundle");
    }

    return enif_make_atom(env, "ok");
}

ERL_NIF_TERM signal_nif_encrypt_message(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 3) {
        return enif_make_badarg(env);
    }

    ErlNifBinary key_bin, iv_bin, data_bin;
    if (!get_binary(env, argv[0], &key_bin) ||
        !get_binary(env, argv[1], &iv_bin) ||
        !get_binary(env, argv[2], &data_bin)) {
        return enif_make_badarg(env);
    }

    aes_key_t key;
    memcpy(key.key, key_bin.data, AES_KEY_SIZE);

    size_t ciphertext_len = data_bin.size + 16;  // Data + MAC
    uint8_t* ciphertext = enif_alloc(ciphertext_len);
    if (!ciphertext) {
        return make_error(env, "failed to allocate ciphertext buffer");
    }

    uint8_t tag[16];
    crypto_error_t result = aes_gcm_encrypt(&key, iv_bin.data, iv_bin.size,
                                          data_bin.data, data_bin.size,
                                          NULL, 0,  // No AAD
                                          ciphertext, &ciphertext_len,
                                          tag, sizeof(tag));
    if (result != CRYPTO_OK) {
        enif_free(ciphertext);
        return make_error(env, "failed to encrypt message");
    }

    ERL_NIF_TERM ciphertext_term = make_binary(env, ciphertext, ciphertext_len);
    enif_free(ciphertext);

    return make_ok(env, ciphertext_term);
}

ERL_NIF_TERM signal_nif_decrypt_message(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 3) {
        return enif_make_badarg(env);
    }

    ErlNifBinary key_bin, iv_bin, ciphertext_bin;
    if (!get_binary(env, argv[0], &key_bin) ||
        !get_binary(env, argv[1], &iv_bin) ||
        !get_binary(env, argv[2], &ciphertext_bin)) {
        return enif_make_badarg(env);
    }

    aes_key_t key;
    memcpy(key.key, key_bin.data, AES_KEY_SIZE);

    size_t message_len = ciphertext_bin.size - 16;  // Remove MAC
    uint8_t* message = enif_alloc(message_len);
    if (!message) {
        return make_error(env, "failed to allocate message buffer");
    }

    uint8_t tag[16];
    memcpy(tag, ciphertext_bin.data + message_len, sizeof(tag));

    crypto_error_t result = aes_gcm_decrypt(&key, iv_bin.data, iv_bin.size,
                                          ciphertext_bin.data, message_len,
                                          NULL, 0,  // No AAD
                                          tag, sizeof(tag),
                                          message, &message_len);
    if (result != CRYPTO_OK) {
        enif_free(message);
        return make_error(env, "failed to decrypt message");
    }

    ERL_NIF_TERM message_term = make_binary(env, message, message_len);
    enif_free(message);

    return make_ok(env, message_term);
}

// Additional NIF functions for crypto operations
ERL_NIF_TERM signal_nif_sign_data(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 2) {
        return enif_make_badarg(env);
    }

    ErlNifBinary private_key_bin, data_bin;
    if (!get_binary(env, argv[0], &private_key_bin) ||
        !get_binary(env, argv[1], &data_bin)) {
        return enif_make_badarg(env);
    }

    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) {
        return make_error(env, "failed to create EC key");
    }

    BIGNUM* bn = BN_bin2bn(private_key_bin.data, private_key_bin.size, NULL);
    if (!bn || !EC_KEY_set_private_key(key, bn)) {
        BN_free(bn);
        EC_KEY_free(key);
        return make_error(env, "failed to set private key");
    }

    ERL_NIF_TERM signature = sign_data(env, key, data_bin.data, data_bin.size);
    BN_free(bn);
    EC_KEY_free(key);

    return signature;
}

ERL_NIF_TERM signal_nif_verify_signature(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 3) {
        return enif_make_badarg(env);
    }

    ErlNifBinary public_key_bin, data_bin, signature_bin;
    if (!get_binary(env, argv[0], &public_key_bin) ||
        !get_binary(env, argv[1], &data_bin) ||
        !get_binary(env, argv[2], &signature_bin)) {
        return enif_make_badarg(env);
    }

    EC_KEY* key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!key) {
        return make_error(env, "failed to create EC key");
    }

    EC_POINT* point = EC_POINT_new(EC_KEY_get0_group(key));
    if (!point) {
        EC_KEY_free(key);
        return make_error(env, "failed to create EC point");
    }

    if (!EC_POINT_oct2point(EC_KEY_get0_group(key), point,
                           public_key_bin.data, public_key_bin.size, NULL)) {
        EC_POINT_free(point);
        EC_KEY_free(key);
        return make_error(env, "failed to set public key");
    }

    if (!EC_KEY_set_public_key(key, point)) {
        EC_POINT_free(point);
        EC_KEY_free(key);
        return make_error(env, "failed to set public key");
    }

    int result = verify_signature(key, data_bin.data, data_bin.size,
                                signature_bin.data, signature_bin.size);
    EC_POINT_free(point);
    EC_KEY_free(key);

    return make_ok(env, enif_make_atom(env, result ? "true" : "false"));
}

ERL_NIF_TERM signal_nif_hmac_sha256(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 2) {
        return enif_make_badarg(env);
    }

    ErlNifBinary key_bin, data_bin;
    if (!get_binary(env, argv[0], &key_bin) ||
        !get_binary(env, argv[1], &data_bin)) {
        return enif_make_badarg(env);
    }

    hmac_key_t key;
    memcpy(key.key, key_bin.data, HMAC_KEY_SIZE);

    uint8_t mac[32];
    size_t mac_len = sizeof(mac);
    crypto_error_t result = hmac_sha256(&key, data_bin.data, data_bin.size,
                                      mac, &mac_len);
    if (result != CRYPTO_OK) {
        return make_error(env, "failed to generate HMAC");
    }

    return make_ok(env, make_binary(env, mac, mac_len));
}

ERL_NIF_TERM signal_nif_sha256(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 1) {
        return enif_make_badarg(env);
    }

    ErlNifBinary data_bin;
    if (!get_binary(env, argv[0], &data_bin)) {
        return enif_make_badarg(env);
    }

    uint8_t digest[32];
    size_t digest_len = sizeof(digest);
    crypto_error_t result = sha256(data_bin.data, data_bin.size,
                                 digest, &digest_len);
    if (result != CRYPTO_OK) {
        return make_error(env, "failed to generate SHA-256 hash");
    }

    return make_ok(env, make_binary(env, digest, digest_len));
}

ERL_NIF_TERM signal_nif_random_bytes(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) {
    if (argc != 1) {
        return enif_make_badarg(env);
    }

    int n;
    if (!enif_get_int(env, argv[0], &n) || n <= 0) {
        return enif_make_badarg(env);
    }

    uint8_t* bytes = enif_alloc(n);
    if (!bytes) {
        return make_error(env, "failed to allocate random bytes buffer");
    }

    crypto_error_t result = crypto_random_bytes(bytes, n);
    if (result != CRYPTO_OK) {
        enif_free(bytes);
        return make_error(env, "failed to generate random bytes");
    }

    ERL_NIF_TERM bytes_term = make_binary(env, bytes, n);
    enif_free(bytes);

    return make_ok(env, bytes_term);
}

// NIF module definition
static ErlNifFunc nif_funcs[] = {
    {"generate_identity_key_pair", 0, signal_nif_generate_identity_key_pair},
    {"generate_pre_key", 1, signal_nif_generate_pre_key},
    {"generate_signed_pre_key", 2, signal_nif_generate_signed_pre_key},
    {"create_session", 3, signal_nif_create_session},
    {"process_pre_key_bundle", 2, signal_nif_process_pre_key_bundle},
    {"encrypt_message", 3, signal_nif_encrypt_message},
    {"decrypt_message", 3, signal_nif_decrypt_message},
    {"sign_data", 2, signal_nif_sign_data},
    {"verify_signature", 3, signal_nif_verify_signature},
    {"hmac_sha256", 2, signal_nif_hmac_sha256},
    {"sha256", 1, signal_nif_sha256},
    {"random_bytes", 1, signal_nif_random_bytes}
};

static int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) {
    signal_store_resource_type = enif_open_resource_type(env, NULL, "signal_store",
                                                       signal_store_dtor,
                                                       ERL_NIF_RT_CREATE,
                                                       NULL);
    if (!signal_store_resource_type) {
        return -1;
    }

    signal_session_resource_type = enif_open_resource_type(env, NULL, "signal_session",
                                                         signal_session_dtor,
                                                         ERL_NIF_RT_CREATE,
                                                         NULL);
    if (!signal_session_resource_type) {
        return -1;
    }

    return 0;
}

static void unload(ErlNifEnv* env, void* priv_data) {
    // Nothing to clean up
}

ERL_NIF_INIT(Elixir.SignalProtocol.Native, nif_funcs, load, NULL, NULL, unload) 