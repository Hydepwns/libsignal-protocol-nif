#include <erl_nif.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#include <stdio.h>
#include "crypto/crypto.h"
#include "protocol/protocol.h"

// Constants
#define MESSAGE_KEY_LEN 32
#define CHAIN_KEY_LEN 32
#define ROOT_KEY_LEN 32
#define MAX_MESSAGE_KEYS 2000
#define MAX_SKIP_KEYS 100
#define RATCHET_ROTATION_THRESHOLD 100
#define CHAIN_KEY_CACHE_SIZE 10
#define ROOT_KEY_CACHE_SIZE 5
#define MIN_CHAIN_KEY_CACHE_SIZE 5
#define MAX_CHAIN_KEY_CACHE_SIZE 20
#define MIN_ROOT_KEY_CACHE_SIZE 3
#define MAX_ROOT_KEY_CACHE_SIZE 10
#define CACHE_GROWTH_FACTOR 1.5
#define CACHE_SHRINK_FACTOR 0.75
#define CACHE_HIT_THRESHOLD 0.7
#define CACHE_MISS_THRESHOLD 0.3

// Forward declarations
static ERL_NIF_TERM make_error(ErlNifEnv *env, const char *reason);
static ERL_NIF_TERM make_ok(ErlNifEnv *env, ERL_NIF_TERM value);
static ERL_NIF_TERM make_binary(ErlNifEnv *env, const unsigned char *data, size_t len);

// Type definitions
typedef struct
{
    unsigned char key[MESSAGE_KEY_LEN];
    uint32_t index;
    uint32_t ratchet_index;
} message_key_t;

typedef struct
{
    EVP_PKEY *dh_key;
    unsigned char chain_key[CHAIN_KEY_LEN];
    uint32_t chain_index;
    message_key_t message_keys[MAX_MESSAGE_KEYS];
    size_t message_key_count;
    message_key_t skip_keys[MAX_SKIP_KEYS];
    size_t skip_key_count;
} ratchet_chain_t;

typedef struct
{
    size_t hits;
    size_t misses;
    size_t current_size;
    size_t max_size;
    double hit_ratio;
    size_t last_adjustment;
} cache_stats_t;

typedef struct
{
    unsigned char chain_key[CHAIN_KEY_LEN];
    uint32_t index;
    uint32_t ratchet_index;
} chain_key_cache_t;

typedef struct
{
    unsigned char root_key[ROOT_KEY_LEN];
    uint32_t ratchet_index;
} root_key_cache_t;

typedef struct
{
    ratchet_chain_t sending_chain;
    ratchet_chain_t receiving_chain;
    unsigned char root_key[ROOT_KEY_LEN];
    uint32_t sending_ratchet_index;
    uint32_t receiving_ratchet_index;
    chain_key_cache_t *chain_key_cache;
    size_t chain_key_cache_size;
    size_t chain_key_cache_count;
    root_key_cache_t *root_key_cache;
    size_t root_key_cache_size;
    size_t root_key_cache_count;
    cache_stats_t chain_key_stats;
    cache_stats_t root_key_stats;
} ratchet_state_t;

// Simple session structure without pointers for serialization
typedef struct
{
    unsigned char root_key[ROOT_KEY_LEN];
    unsigned char sending_chain_key[CHAIN_KEY_LEN];
    uint32_t sending_chain_index;
    uint32_t sending_ratchet_index;
    uint32_t receiving_ratchet_index;
    // Store the ephemeral key as raw bytes instead of pointer
    unsigned char ephemeral_key[CURVE25519_KEY_SIZE];
} simple_session_t;

// OpenSSL initialization function
static int init_openssl(void)
{
    // Initialize OpenSSL with all required subsystems
    if (!OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS |
                                 OPENSSL_INIT_ADD_ALL_DIGESTS |
                                 OPENSSL_INIT_LOAD_CONFIG,
                             NULL))
    {
        return 0;
    }

    // Note: ERR_load_crypto_strings() and OpenSSL_add_all_algorithms()
    // are deprecated in OpenSSL 3.x and not needed with OPENSSL_init_crypto()

    return 1;
}

// OpenSSL cleanup function
static void cleanup_openssl(void)
{
    // Note: EVP_cleanup() and ERR_free_strings() are deprecated in OpenSSL 3.x
    // and not needed with OPENSSL_init_crypto()
    // OpenSSL 3.x handles cleanup automatically
}

// Enhanced error handling function
static ERL_NIF_TERM make_openssl_error(ErlNifEnv *env)
{
    unsigned long err;
    char err_buf[256];

    err = ERR_get_error();
    if (err)
    {
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        fprintf(stderr, "[NIF DEBUG] OpenSSL error: %s\n", err_buf);
        return make_error(env, err_buf);
    }
    fprintf(stderr, "[NIF DEBUG] OpenSSL error: Unknown error\n");
    return make_error(env, "Unknown OpenSSL error");
}

// Helper function to check OpenSSL errors
/*
static int check_openssl_error(ErlNifEnv* env) {
    unsigned long err = ERR_get_error();
    if (err != 0) {
        char err_buf[256];
        ERR_error_string_n(err, err_buf, sizeof(err_buf));
        return make_error(env, err_buf);
    }
    return 0;
}
*/

// Key validation constants
#define MIN_KEY_SIZE 32      // Minimum key size in bytes (Curve25519)
#define MAX_KEY_SIZE 32      // Maximum key size in bytes (Curve25519)
#define CURVE_NID NID_X25519 // Curve25519 curve

// Scrypt parameters
#define SCRYPT_N 32768
#define SCRYPT_R 8
#define SCRYPT_P 1

// Header size: 8 bytes for indices, 32 for Curve25519 public key
#define HEADER_SIZE (8 + 32)

// Key validation functions
static int validate_ec_key(EVP_PKEY *key)
{
    if (!key)
    {
        return 0;
    }

    // Check if key is valid using EVP_PKEY API
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx)
    {
        return 0;
    }

    int result = EVP_PKEY_check(ctx);
    EVP_PKEY_CTX_free(ctx);

    if (result <= 0)
    {
        return 0;
    }

    // Verify key type is Curve25519 (X25519)
    if (EVP_PKEY_id(key) != EVP_PKEY_X25519)
    {
        return 0;
    }

    return 1;
}

static int validate_public_key_data(const unsigned char *key_data, size_t key_len)
{
    if (!key_data || key_len != CURVE25519_KEY_SIZE)
    {
        return 0;
    }

    // For Curve25519, we just check the size since it's a raw public key
    // No specific format validation needed like P-256's 0x04 prefix
    return 1;
}

// NIF function declarations
static ERL_NIF_TERM generate_identity_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM generate_pre_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM generate_signed_pre_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM create_session(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM process_pre_key_bundle(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM encrypt_message(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM decrypt_message(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM get_cache_stats(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM reset_cache_stats(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM set_cache_size(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM verify_signature(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM compute_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

// NIF function definitions
static ErlNifFunc nif_funcs[] = {
    {"generate_identity_key_pair", 0, generate_identity_key_pair, 0},
    {"generate_pre_key", 1, generate_pre_key, 0},
    {"generate_signed_pre_key", 2, generate_signed_pre_key, 0},
    {"create_session", 1, create_session, 0},
    {"process_pre_key_bundle", 2, process_pre_key_bundle, 0},
    {"encrypt_message", 2, encrypt_message, 0},
    {"decrypt_message", 2, decrypt_message, 0},
    {"verify_signature", 3, verify_signature, 0},
    {"compute_key", 4, compute_key, 0},
    {"get_cache_stats", 1, get_cache_stats, 0},
    {"reset_cache_stats", 1, reset_cache_stats, 0},
    {"set_cache_size", 3, set_cache_size, 0}};

// Module load callback
static int on_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    (void)env;
    (void)priv_data;
    (void)load_info;
    fprintf(stderr, "[NIF DEBUG] on_load called\n");
    fprintf(stderr, "[NIF DEBUG] OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));
    if (!init_openssl())
    {
        fprintf(stderr, "[NIF DEBUG] on_load: init_openssl failed\n");
        return -1;
    }
    fprintf(stderr, "[NIF DEBUG] on_load: success\n");
    return 0;
}

// Module unload callback
static void on_unload(ErlNifEnv *env, void *priv_data)
{
    (void)env;
    (void)priv_data;
    cleanup_openssl();
}

// NIF module definition with unload callback
ERL_NIF_INIT(nif, nif_funcs, on_load, NULL, NULL, on_unload)

// Helper functions
static ERL_NIF_TERM make_error(ErlNifEnv *env, const char *reason)
{
    return enif_make_tuple2(env,
                            enif_make_atom(env, "error"),
                            enif_make_string(env, reason, ERL_NIF_LATIN1));
}

static ERL_NIF_TERM make_ok(ErlNifEnv *env, ERL_NIF_TERM value)
{
    return enif_make_tuple2(env,
                            enif_make_atom(env, "ok"),
                            value);
}

static ERL_NIF_TERM make_binary(ErlNifEnv *env, const unsigned char *data, size_t len)
{
    ERL_NIF_TERM binary;
    unsigned char *buffer = enif_make_new_binary(env, len, &binary);
    memcpy(buffer, data, len);
    return binary;
}

// Key generation functions
static int generate_ec_key_pair(EVP_PKEY **key)
{
    EVP_PKEY *public_key = NULL, *private_key = NULL;
    fprintf(stderr, "[NIF DEBUG] generate_ec_key_pair: calling curve25519_generate_keypair\n");

    // Use Curve25519 instead of P-256
    curve25519_key_t pub_key, priv_key;
    crypto_error_t result = curve25519_generate_keypair(&pub_key, &priv_key);
    fprintf(stderr, "[NIF DEBUG] generate_ec_key_pair: curve25519_generate_keypair result = %d\n", result);
    if (result != CRYPTO_OK)
    {
        fprintf(stderr, "[NIF DEBUG] generate_ec_key_pair: key generation failed\n");
        return 0;
    }

    // Create EVP_PKEY from Curve25519 private key
    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv_key.key, CURVE25519_KEY_SIZE);
    if (!pkey)
    {
        fprintf(stderr, "[NIF DEBUG] generate_ec_key_pair: failed to create EVP_PKEY\n");
        return 0;
    }

    *key = pkey;
    fprintf(stderr, "[NIF DEBUG] generate_ec_key_pair: key generation succeeded\n");
    return 1;
}

static int generate_ed25519_key_pair(EVP_PKEY **key)
{
    fprintf(stderr, "[NIF DEBUG] generate_ed25519_key_pair: generating Ed25519 key pair\n");

    // Create EVP_PKEY context for Ed25519 key generation
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    if (!pctx)
    {
        fprintf(stderr, "[NIF DEBUG] generate_ed25519_key_pair: failed to create context\n");
        return 0;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0)
    {
        fprintf(stderr, "[NIF DEBUG] generate_ed25519_key_pair: failed to init keygen\n");
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
    {
        fprintf(stderr, "[NIF DEBUG] generate_ed25519_key_pair: failed to generate key\n");
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }

    EVP_PKEY_CTX_free(pctx);
    *key = pkey;
    fprintf(stderr, "[NIF DEBUG] generate_ed25519_key_pair: key generation succeeded\n");
    return 1;
}

static ERL_NIF_TERM key_to_binary(ErlNifEnv *env, EVP_PKEY *key, int is_public)
{
    int key_type = EVP_PKEY_id(key);

    if (key_type == EVP_PKEY_X25519)
    {
        // Handle X25519 keys (for key exchange)
        if (is_public)
        {
            // For Curve25519 public key, extract raw public key
            uint8_t buffer[CURVE25519_KEY_SIZE];
            size_t buffer_len = sizeof(buffer);
            fprintf(stderr, "[NIF DEBUG] key_to_binary: serializing Curve25519 public key\n");

            if (EVP_PKEY_get_raw_public_key(key, buffer, &buffer_len) <= 0 || buffer_len != CURVE25519_KEY_SIZE)
            {
                fprintf(stderr, "[NIF DEBUG] key_to_binary: failed to get raw public key\n");
                return make_error(env, "Failed to serialize public key");
            }

            ERL_NIF_TERM binary;
            unsigned char *bin_buffer = enif_make_new_binary(env, buffer_len, &binary);
            if (!bin_buffer)
            {
                fprintf(stderr, "[NIF DEBUG] key_to_binary: failed to allocate binary for public key\n");
                return make_error(env, "Failed to allocate binary");
            }
            memcpy(bin_buffer, buffer, buffer_len);
            return binary;
        }
        else
        {
            // For Curve25519 private key, extract raw private key
            uint8_t buffer[CURVE25519_KEY_SIZE];
            size_t buffer_len = sizeof(buffer);
            fprintf(stderr, "[NIF DEBUG] key_to_binary: serializing Curve25519 private key\n");

            if (EVP_PKEY_get_raw_private_key(key, buffer, &buffer_len) <= 0 || buffer_len != CURVE25519_KEY_SIZE)
            {
                fprintf(stderr, "[NIF DEBUG] key_to_binary: failed to get raw private key\n");
                return make_error(env, "Failed to serialize private key");
            }

            ERL_NIF_TERM binary;
            unsigned char *bin_buffer = enif_make_new_binary(env, buffer_len, &binary);
            if (!bin_buffer)
            {
                fprintf(stderr, "[NIF DEBUG] key_to_binary: failed to allocate binary for private key\n");
                return make_error(env, "Failed to allocate binary");
            }
            memcpy(bin_buffer, buffer, buffer_len);
            return binary;
        }
    }
    else if (key_type == EVP_PKEY_ED25519)
    {
        // Handle Ed25519 keys (for signing)
        if (is_public)
        {
            // For Ed25519 public key, extract raw public key
            uint8_t buffer[CURVE25519_KEY_SIZE];
            size_t buffer_len = sizeof(buffer);
            fprintf(stderr, "[NIF DEBUG] key_to_binary: serializing Ed25519 public key\n");

            if (EVP_PKEY_get_raw_public_key(key, buffer, &buffer_len) <= 0 || buffer_len != CURVE25519_KEY_SIZE)
            {
                fprintf(stderr, "[NIF DEBUG] key_to_binary: failed to get raw Ed25519 public key\n");
                return make_error(env, "Failed to serialize Ed25519 public key");
            }

            ERL_NIF_TERM binary;
            unsigned char *bin_buffer = enif_make_new_binary(env, buffer_len, &binary);
            if (!bin_buffer)
            {
                fprintf(stderr, "[NIF DEBUG] key_to_binary: failed to allocate binary for Ed25519 public key\n");
                return make_error(env, "Failed to allocate binary");
            }
            memcpy(bin_buffer, buffer, buffer_len);
            return binary;
        }
        else
        {
            // For Ed25519 private key, extract raw private key and public key
            // Erlang's crypto:sign/verify expects 64-byte private key (private + public concatenated)
            uint8_t private_buffer[CURVE25519_KEY_SIZE];
            uint8_t public_buffer[CURVE25519_KEY_SIZE];
            uint8_t combined_buffer[CURVE25519_KEY_SIZE * 2]; // 64 bytes
            size_t private_len = sizeof(private_buffer);
            size_t public_len = sizeof(public_buffer);
            fprintf(stderr, "[NIF DEBUG] key_to_binary: serializing Ed25519 private key (64-byte format)\n");

            if (EVP_PKEY_get_raw_private_key(key, private_buffer, &private_len) <= 0 || private_len != CURVE25519_KEY_SIZE)
            {
                fprintf(stderr, "[NIF DEBUG] key_to_binary: failed to get raw Ed25519 private key\n");
                return make_error(env, "Failed to serialize Ed25519 private key");
            }

            if (EVP_PKEY_get_raw_public_key(key, public_buffer, &public_len) <= 0 || public_len != CURVE25519_KEY_SIZE)
            {
                fprintf(stderr, "[NIF DEBUG] key_to_binary: failed to get raw Ed25519 public key\n");
                return make_error(env, "Failed to serialize Ed25519 public key");
            }

            // Concatenate private key (32 bytes) + public key (32 bytes) = 64 bytes
            memcpy(combined_buffer, private_buffer, CURVE25519_KEY_SIZE);
            memcpy(combined_buffer + CURVE25519_KEY_SIZE, public_buffer, CURVE25519_KEY_SIZE);

            ERL_NIF_TERM binary;
            unsigned char *bin_buffer = enif_make_new_binary(env, CURVE25519_KEY_SIZE * 2, &binary);
            if (!bin_buffer)
            {
                fprintf(stderr, "[NIF DEBUG] key_to_binary: failed to allocate binary for Ed25519 private key\n");
                return make_error(env, "Failed to allocate binary");
            }
            memcpy(bin_buffer, combined_buffer, CURVE25519_KEY_SIZE * 2);
            return binary;
        }
    }
    else
    {
        fprintf(stderr, "[NIF DEBUG] key_to_binary: unsupported key type %d\n", key_type);
        return make_error(env, "Unsupported key type");
    }
}

// Cryptographic functions
static ERL_NIF_TERM sign_data(ErlNifEnv *env, EVP_PKEY *key, const unsigned char *data, size_t data_len)
{
    uint8_t signature[EC_SIGNATURE_SIZE];
    size_t signature_len = sizeof(signature);

    fprintf(stderr, "[NIF DEBUG] sign_data: data_len=%zu, signature_len=%zu\n", data_len, signature_len);

    crypto_error_t result = evp_sign_data(key, data, data_len, signature, &signature_len);
    if (result != CRYPTO_OK)
    {
        fprintf(stderr, "[NIF DEBUG] sign_data: evp_sign_data failed with error %d\n", result);
        return make_error(env, "Failed to sign data");
    }

    fprintf(stderr, "[NIF DEBUG] sign_data: signature generated, length=%zu\n", signature_len);

    ERL_NIF_TERM signature_term;
    unsigned char *buffer = enif_make_new_binary(env, signature_len, &signature_term);
    if (!buffer)
    {
        fprintf(stderr, "[NIF DEBUG] sign_data: failed to allocate signature buffer\n");
        return make_error(env, "Failed to allocate signature buffer");
    }

    memcpy(buffer, signature, signature_len);
    fprintf(stderr, "[NIF DEBUG] sign_data: returning signature binary\n");
    return signature_term;
}

/*
static int verify_signature(EC_KEY* key, const unsigned char* data, size_t data_len,
                          const unsigned char* signature, size_t signature_len) {
    ECDSA_SIG* sig = ECDSA_SIG_new();
    if (!sig) {
        return 0;
    }

    BIGNUM* r = BN_new();
    BIGNUM* s = BN_new();
    if (!r || !s) {
        ECDSA_SIG_free(sig);
        return 0;
    }

    size_t r_len = signature_len / 2;
    size_t s_len = signature_len - r_len;

    if (!BN_bin2bn(signature, r_len, r) || !BN_bin2bn(signature + r_len, s_len, s)) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig);
        return 0;
    }

    if (!ECDSA_SIG_set0(sig, r, s)) {
        ECDSA_SIG_free(sig);
        return 0;
    }

    int result = ECDSA_do_verify(data, data_len, sig, key);
    ECDSA_SIG_free(sig);
    return result == 1;
}
*/

// Key derivation constants
#define HKDF_INFO_LEN 1
#define ROOT_KEY_LEN 32
#define CHAIN_KEY_LEN 32
#define MESSAGE_KEY_LEN 32

// Forward declarations for static functions
static void cleanup_message_keys(ratchet_chain_t *chain);
static void cleanup_skip_keys(ratchet_chain_t *chain);
static void adjust_cache_size(cache_stats_t *stats, size_t *cache_size);
static void add_root_key_to_cache(ratchet_state_t *state, const unsigned char *root_key, uint32_t ratchet_index);

// Key derivation functions
static int derive_root_key(const unsigned char *dh_output, size_t dh_output_len,
                           const unsigned char *salt, size_t salt_len,
                           unsigned char *root_key)
{
    // Use simple HMAC-SHA256 for key derivation
    const unsigned char info[] = "RootKey";
    size_t info_len = sizeof(info) - 1; // Exclude null terminator

    // Use salt as HMAC key, or default to zeros if no salt
    unsigned char hmac_key[32] = {0};
    if (salt && salt_len > 0)
    {
        size_t copy_len = (salt_len > 32) ? 32 : salt_len;
        memcpy(hmac_key, salt, copy_len);
    }

    // HMAC(dh_output, info)
    unsigned char hmac_result[32];
    unsigned int hmac_len = sizeof(hmac_result);

    if (!HMAC(EVP_sha256(), hmac_key, sizeof(hmac_key),
              dh_output, dh_output_len,
              hmac_result, &hmac_len))
    {
        return 0;
    }

    // Use the HMAC result as the root key
    memcpy(root_key, hmac_result, ROOT_KEY_LEN);
    return 1;
}

static int derive_chain_key(const unsigned char *root_key, size_t root_key_len,
                            const unsigned char *salt, size_t salt_len,
                            unsigned char *chain_key)
{
    // Use simple HMAC-SHA256 for key derivation
    const unsigned char info[] = "ChainKey";
    size_t info_len = sizeof(info) - 1; // Exclude null terminator

    // Use salt as HMAC key, or default to zeros if no salt
    unsigned char hmac_key[32] = {0};
    if (salt && salt_len > 0)
    {
        size_t copy_len = (salt_len > 32) ? 32 : salt_len;
        memcpy(hmac_key, salt, copy_len);
    }

    // HMAC(root_key, info)
    unsigned char hmac_result[32];
    unsigned int hmac_len = sizeof(hmac_result);

    if (!HMAC(EVP_sha256(), hmac_key, sizeof(hmac_key),
              root_key, root_key_len,
              hmac_result, &hmac_len))
    {
        return 0;
    }

    // Use the HMAC result as the chain key
    memcpy(chain_key, hmac_result, CHAIN_KEY_LEN);
    return 1;
}

static int derive_message_key(const unsigned char *chain_key, size_t chain_key_len,
                              const unsigned char *salt, size_t salt_len,
                              unsigned char *message_key)
{
    // Use simple HMAC-SHA256 for key derivation
    const unsigned char info[] = "MessageKey";
    size_t info_len = sizeof(info) - 1; // Exclude null terminator

    // Use salt as HMAC key, or default to zeros if no salt
    unsigned char hmac_key[32] = {0};
    if (salt && salt_len > 0)
    {
        size_t copy_len = (salt_len > 32) ? 32 : salt_len;
        memcpy(hmac_key, salt, copy_len);
    }

    // HMAC(chain_key, info)
    unsigned char hmac_result[32];
    unsigned int hmac_len = sizeof(hmac_result);

    if (!HMAC(EVP_sha256(), hmac_key, sizeof(hmac_key),
              chain_key, chain_key_len,
              hmac_result, &hmac_len))
    {
        return 0;
    }

    // Use the HMAC result as the message key
    memcpy(message_key, hmac_result, MESSAGE_KEY_LEN);
    return 1;
}

static int calculate_dh_shared_secret(EVP_PKEY *our_key, EVP_PKEY *their_key,
                                      unsigned char *shared_secret, size_t *shared_secret_len)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(our_key, NULL);
    if (!ctx)
    {
        return 0;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_derive_set_peer(ctx, their_key) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_derive(ctx, shared_secret, shared_secret_len) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);
    return 1;
}

// Bundle parsing helper functions
static int parse_uint32(const unsigned char *data, uint32_t *value)
{
    if (!data || !value)
        return 0;
    *value = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    return 1;
}

static int parse_binary(const unsigned char *data, size_t data_len, size_t *offset,
                        unsigned char **binary, size_t *binary_len)
{
    if (!data || !offset || !binary || !binary_len || *offset + 4 > data_len)
    {
        return 0;
    }

    uint32_t len;
    if (!parse_uint32(data + *offset, &len))
    {
        return 0;
    }
    *offset += 4;

    if (*offset + len > data_len)
    {
        return 0;
    }

    *binary = (unsigned char *)data + *offset;
    *binary_len = len;
    *offset += len;
    return 1;
}

// Ratchet constants
#define MAX_SKIP 1000

// Message key skipping constants
#define MAX_SKIP_DISTANCE 1000

// Message key cleanup constants
#define MESSAGE_KEY_CLEANUP_THRESHOLD 1000
#define SKIP_KEY_CLEANUP_THRESHOLD 50
#define MAX_KEY_AGE 10000

// Ratchet functions
static int rotate_chain_key(ratchet_chain_t *chain)
{
    // Check if we can use cached chain key
    if (chain->chain_index + 1 < RATCHET_ROTATION_THRESHOLD)
    {
        unsigned char new_chain_key[CHAIN_KEY_LEN];
        const unsigned char salt[] = "ChainKey";
        if (!derive_chain_key(chain->chain_key, CHAIN_KEY_LEN,
                              salt, sizeof(salt), new_chain_key))
        {
            return 0;
        }
        memcpy(chain->chain_key, new_chain_key, CHAIN_KEY_LEN);
        chain->chain_index++;
        return 1;
    }
    return 0;
}

static int add_message_key(ratchet_chain_t *chain, const unsigned char *message_key)
{
    if (chain->message_key_count >= MAX_MESSAGE_KEYS)
    {
        return 0;
    }

    memcpy(chain->message_keys[chain->message_key_count].key, message_key, MESSAGE_KEY_LEN);
    chain->message_keys[chain->message_key_count].index = chain->chain_index;
    chain->message_keys[chain->message_key_count].ratchet_index = chain->chain_index;
    chain->message_key_count++;

    // Cleanup if we're approaching the limit
    if (chain->message_key_count >= MESSAGE_KEY_CLEANUP_THRESHOLD)
    {
        cleanup_message_keys(chain);
    }

    return 1;
}

/*
static int get_message_key(ratchet_chain_t* chain, uint32_t index, unsigned char* message_key) {
    if (index < chain->index) {
        return 0;
    }

    while (chain->index < index) {
        if (!derive_chain_key(chain->chain_key, CHAIN_KEY_LEN, NULL, 0, chain->chain_key)) {
            return 0;
        }
        chain->index++;
    }

    return derive_message_key(chain->chain_key, CHAIN_KEY_LEN, NULL, 0, message_key);
}
*/

static int rotate_sending_ratchet(ratchet_state_t *state)
{
    // Generate new DH key pair
    EVP_PKEY *new_dh_key = NULL;
    if (!generate_ec_key_pair(&new_dh_key))
    {
        return 0;
    }

    // Calculate new shared secret
    unsigned char shared_secret[32];
    size_t shared_secret_len = sizeof(shared_secret);
    if (!calculate_dh_shared_secret(new_dh_key, state->receiving_chain.dh_key, shared_secret, &shared_secret_len))
    {
        EVP_PKEY_free(new_dh_key);
        return 0;
    }

    // Derive new root key
    unsigned char new_root_key[ROOT_KEY_LEN];
    if (!derive_root_key(shared_secret, shared_secret_len,
                         NULL, 0, new_root_key))
    {
        EVP_PKEY_free(new_dh_key);
        return 0;
    }

    // Cache the new root key
    add_root_key_to_cache(state, new_root_key, state->sending_ratchet_index + 1);

    // Update state
    memcpy(state->root_key, new_root_key, ROOT_KEY_LEN);
    if (state->sending_chain.dh_key)
    {
        EVP_PKEY_free(state->sending_chain.dh_key);
    }
    state->sending_chain.dh_key = new_dh_key;
    state->sending_ratchet_index++;

    // Reset sending chain
    memset(state->sending_chain.chain_key, 0, CHAIN_KEY_LEN);
    state->sending_chain.chain_index = 0;

    return 1;
}

static int rotate_receiving_ratchet(ratchet_state_t *state, EVP_PKEY *their_dh_key)
{
    if (!their_dh_key)
    {
        return 0;
    }

    // Validate their DH key
    if (!validate_ec_key(their_dh_key))
    {
        return 0;
    }

    // Generate new DH key pair
    EVP_PKEY *new_dh_key = NULL;
    if (!generate_ec_key_pair(&new_dh_key))
    {
        return 0;
    }

    // Validate our new key
    if (!validate_ec_key(new_dh_key))
    {
        EVP_PKEY_free(new_dh_key);
        return 0;
    }

    // Calculate new shared secret
    unsigned char shared_secret[32];
    size_t shared_secret_len = sizeof(shared_secret);
    if (!calculate_dh_shared_secret(new_dh_key, their_dh_key, shared_secret, &shared_secret_len))
    {
        EVP_PKEY_free(new_dh_key);
        return 0;
    }

    // Verify shared secret size
    if (shared_secret_len != MIN_KEY_SIZE)
    {
        EVP_PKEY_free(new_dh_key);
        return 0;
    }

    // Derive new root key
    unsigned char new_root_key[ROOT_KEY_LEN];
    if (!derive_root_key(shared_secret, shared_secret_len,
                         NULL, 0, new_root_key))
    {
        EVP_PKEY_free(new_dh_key);
        return 0;
    }

    // Cache the new root key
    add_root_key_to_cache(state, new_root_key, state->receiving_ratchet_index + 1);

    // Update state
    memcpy(state->root_key, new_root_key, ROOT_KEY_LEN);
    if (state->receiving_chain.dh_key)
    {
        EVP_PKEY_free(state->receiving_chain.dh_key);
    }
    state->receiving_chain.dh_key = new_dh_key;
    state->receiving_ratchet_index++;

    // Reset receiving chain
    memset(state->receiving_chain.chain_key, 0, CHAIN_KEY_LEN);
    state->receiving_chain.chain_index = 0;

    return 1;
}

// Message key skipping functions
/*
static int add_skip_key(ratchet_chain_t* chain, const unsigned char* message_key,
                       uint32_t index, uint32_t ratchet_index) {
    if (chain->skip_key_count >= MAX_SKIP_KEYS) {
        return 0;
    }

    // Check if we already have this key
    for (size_t i = 0; i < chain->skip_key_count; i++) {
        if (chain->skip_keys[i].index == index &&
            chain->skip_keys[i].ratchet_index == ratchet_index) {
            return 1; // Key already exists
        }
    }

    // Add new skip key
    memcpy(chain->skip_keys[chain->skip_key_count].key, message_key, MESSAGE_KEY_LEN);
    chain->skip_keys[chain->skip_key_count].index = index;
    chain->skip_keys[chain->skip_key_count].ratchet_index = ratchet_index;
    chain->skip_key_count++;

    // Cleanup if we're approaching the limit
    if (chain->skip_key_count >= SKIP_KEY_CLEANUP_THRESHOLD) {
        cleanup_skip_keys(chain);
    }

    return 1;
}
*/

/*
static int get_skip_key(ratchet_chain_t* chain, uint32_t index, uint32_t ratchet_index,
                       unsigned char* skip_key) {
    if (index < chain->index) {
        return 0;
    }

    if (index - chain->index > MAX_SKIP) {
        return 0;
    }

    return derive_skip_key(chain->chain_key, CHAIN_KEY_LEN, index, ratchet_index, skip_key);
}
*/

/*
static int derive_skip_keys(ratchet_chain_t* chain, uint32_t target_index,
                          uint32_t ratchet_index) {
    if (target_index <= chain->chain_index) {
        return 1; // No need to derive skip keys
    }

    if (target_index - chain->chain_index > MAX_SKIP_DISTANCE) {
        return 0; // Target index too far ahead
    }

    unsigned char current_chain_key[CHAIN_KEY_LEN];
    memcpy(current_chain_key, chain->chain_key, CHAIN_KEY_LEN);
    uint32_t current_index = chain->chain_index;

    while (current_index < target_index) {
        // Derive message key
        unsigned char message_key[MESSAGE_KEY_LEN];
        const unsigned char salt[] = "MessageKey";
        if (!derive_message_key(current_chain_key, CHAIN_KEY_LEN,
                              salt, sizeof(salt), message_key)) {
            return 0;
        }

        // Store skip key
        if (!add_skip_key(chain, message_key, current_index, ratchet_index)) {
            return 0;
        }

        // Update chain key
        if (!rotate_chain_key(chain)) {
            return 0;
        }

        memcpy(current_chain_key, chain->chain_key, CHAIN_KEY_LEN);
        current_index++;
    }

    return 1;
}
*/

// Message key cleanup functions
static void cleanup_message_keys(ratchet_chain_t *chain)
{
    if (chain->message_key_count < MESSAGE_KEY_CLEANUP_THRESHOLD)
    {
        return;
    }

    // Find the oldest key that's still needed
    uint32_t oldest_needed = chain->chain_index;
    if (oldest_needed > MAX_KEY_AGE)
    {
        oldest_needed -= MAX_KEY_AGE;
    }

    // Remove old message keys
    size_t i = 0;
    while (i < chain->message_key_count)
    {
        if (chain->message_keys[i].index < oldest_needed)
        {
            // Move the last key to this position
            if (i < chain->message_key_count - 1)
            {
                memcpy(&chain->message_keys[i],
                       &chain->message_keys[chain->message_key_count - 1],
                       sizeof(message_key_t));
            }
            chain->message_key_count--;
        }
        else
        {
            i++;
        }
    }
}

static void cleanup_skip_keys(ratchet_chain_t *chain)
{
    if (chain->skip_key_count < SKIP_KEY_CLEANUP_THRESHOLD)
    {
        return;
    }

    // Find the oldest key that's still needed
    uint32_t oldest_needed = chain->chain_index;
    if (oldest_needed > MAX_KEY_AGE)
    {
        oldest_needed -= MAX_KEY_AGE;
    }

    // Remove old skip keys
    size_t i = 0;
    while (i < chain->skip_key_count)
    {
        if (chain->skip_keys[i].index < oldest_needed)
        {
            // Move the last key to this position
            if (i < chain->skip_key_count - 1)
            {
                memcpy(&chain->skip_keys[i],
                       &chain->skip_keys[chain->skip_key_count - 1],
                       sizeof(message_key_t));
            }
            chain->skip_key_count--;
        }
        else
        {
            i++;
        }
    }
}

static void cleanup_keys(ratchet_state_t *state)
{
    cleanup_message_keys(&state->sending_chain);
    cleanup_message_keys(&state->receiving_chain);
    cleanup_skip_keys(&state->sending_chain);
    cleanup_skip_keys(&state->receiving_chain);

    // Adjust cache sizes based on usage
    adjust_cache_size(&state->chain_key_stats, &state->chain_key_cache_size);
    adjust_cache_size(&state->root_key_stats, &state->root_key_cache_size);
}

// Adaptive cache sizing functions
/*
static void init_cache_stats(cache_stats_t* stats, size_t initial_size, size_t max_size) {
    stats->hits = 0;
    stats->misses = 0;
    stats->current_size = initial_size;
    stats->max_size = max_size;
    stats->hit_ratio = 0.0;
    stats->last_adjustment = 0;
}
*/

static void update_cache_stats(cache_stats_t *stats, int hit)
{
    if (hit)
    {
        stats->hits++;
    }
    else
    {
        stats->misses++;
    }

    size_t total = stats->hits + stats->misses;
    if (total > 0)
    {
        stats->hit_ratio = (double)stats->hits / total;
    }
}

static void adjust_cache_size(cache_stats_t *stats, size_t *cache_size)
{
    // Only adjust after significant number of operations
    if (stats->hits + stats->misses < 100)
    {
        return;
    }

    // Check if we need to grow the cache
    if (stats->hit_ratio > CACHE_HIT_THRESHOLD &&
        stats->current_size < stats->max_size)
    {
        size_t new_size = (size_t)(stats->current_size * CACHE_GROWTH_FACTOR);
        if (new_size > stats->max_size)
        {
            new_size = stats->max_size;
        }
        if (new_size > stats->current_size)
        {
            stats->current_size = new_size;
            *cache_size = new_size;
            stats->last_adjustment = stats->hits + stats->misses;
        }
    }
    // Check if we need to shrink the cache
    else if (stats->hit_ratio < CACHE_MISS_THRESHOLD &&
             stats->current_size > MIN_CHAIN_KEY_CACHE_SIZE)
    {
        size_t new_size = (size_t)(stats->current_size * CACHE_SHRINK_FACTOR);
        if (new_size < MIN_CHAIN_KEY_CACHE_SIZE)
        {
            new_size = MIN_CHAIN_KEY_CACHE_SIZE;
        }
        if (new_size < stats->current_size)
        {
            stats->current_size = new_size;
            *cache_size = new_size;
            stats->last_adjustment = stats->hits + stats->misses;
        }
    }
}

// Update get_cached_chain_key to use adaptive sizing
static int get_cached_chain_key(ratchet_state_t *state, uint32_t index, uint32_t ratchet_index,
                                unsigned char *chain_key)
{
    for (size_t i = 0; i < state->chain_key_cache_count; i++)
    {
        if (state->chain_key_cache[i].index == index &&
            state->chain_key_cache[i].ratchet_index == ratchet_index)
        {
            memcpy(chain_key, state->chain_key_cache[i].chain_key, CHAIN_KEY_LEN);
            update_cache_stats(&state->chain_key_stats, 1);
            return 1;
        }
    }
    update_cache_stats(&state->chain_key_stats, 0);
    adjust_cache_size(&state->chain_key_stats, &state->chain_key_cache_size);
    return 0;
}

// Update add_chain_key_to_cache to use adaptive sizing
static void add_chain_key_to_cache(ratchet_state_t *state, const unsigned char *chain_key,
                                   uint32_t index, uint32_t ratchet_index)
{
    // Check if we need to resize the cache
    if (state->chain_key_cache_count >= state->chain_key_cache_size)
    {
        size_t new_size = state->chain_key_cache_size;
        adjust_cache_size(&state->chain_key_stats, &new_size);

        if (new_size > state->chain_key_cache_size)
        {
            chain_key_cache_t *new_cache = OPENSSL_malloc(new_size * sizeof(chain_key_cache_t));
            if (new_cache)
            {
                memcpy(new_cache, state->chain_key_cache,
                       state->chain_key_cache_count * sizeof(chain_key_cache_t));
                OPENSSL_free(state->chain_key_cache);
                state->chain_key_cache = new_cache;
                state->chain_key_cache_size = new_size;
            }
        }
        else
        {
            // Remove oldest entries if we can't grow
            size_t to_remove = state->chain_key_cache_count - new_size + 1;
            memmove(&state->chain_key_cache[0],
                    &state->chain_key_cache[to_remove],
                    (state->chain_key_cache_count - to_remove) * sizeof(chain_key_cache_t));
            state->chain_key_cache_count -= to_remove;
        }
    }

    // Add new entry
    memcpy(state->chain_key_cache[state->chain_key_cache_count].chain_key,
           chain_key, CHAIN_KEY_LEN);
    state->chain_key_cache[state->chain_key_cache_count].index = index;
    state->chain_key_cache[state->chain_key_cache_count].ratchet_index = ratchet_index;
    state->chain_key_cache_count++;
}

// Update get_cached_root_key to use adaptive sizing
/*
static int get_cached_root_key(ratchet_state_t* state, uint32_t ratchet_index,
                              unsigned char* root_key) {
    if (ratchet_index < state->ratchet_index) {
        return 0;
    }

    if (ratchet_index - state->ratchet_index > MAX_SKIP) {
        return 0;
    }

    return derive_root_key(state->root_key, ROOT_KEY_LEN, NULL, 0, root_key);
}
*/

// Update add_root_key_to_cache to use adaptive sizing
static void add_root_key_to_cache(ratchet_state_t *state, const unsigned char *root_key,
                                  uint32_t ratchet_index)
{
    // Check if we need to resize the cache
    if (state->root_key_cache_count >= state->root_key_cache_size)
    {
        size_t new_size = state->root_key_cache_size;
        adjust_cache_size(&state->root_key_stats, &new_size);

        if (new_size > state->root_key_cache_size)
        {
            root_key_cache_t *new_cache = OPENSSL_malloc(new_size * sizeof(root_key_cache_t));
            if (new_cache)
            {
                memcpy(new_cache, state->root_key_cache,
                       state->root_key_cache_count * sizeof(root_key_cache_t));
                OPENSSL_free(state->root_key_cache);
                state->root_key_cache = new_cache;
                state->root_key_cache_size = new_size;
            }
        }
        else
        {
            // Remove oldest entries if we can't grow
            size_t to_remove = state->root_key_cache_count - new_size + 1;
            memmove(&state->root_key_cache[0],
                    &state->root_key_cache[to_remove],
                    (state->root_key_cache_count - to_remove) * sizeof(root_key_cache_t));
            state->root_key_cache_count -= to_remove;
        }
    }

    // Add new entry
    memcpy(state->root_key_cache[state->root_key_cache_count].root_key,
           root_key, ROOT_KEY_LEN);
    state->root_key_cache[state->root_key_cache_count].ratchet_index = ratchet_index;
    state->root_key_cache_count++;
}

// NIF implementations
static ERL_NIF_TERM generate_identity_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argc;
    (void)argv;
    EVP_PKEY *key;
    ERL_NIF_TERM public_key, private_key;

    fprintf(stderr, "[NIF DEBUG] generate_identity_key_pair: starting key generation\n");

    if (!generate_ec_key_pair(&key))
    {
        fprintf(stderr, "[NIF DEBUG] generate_identity_key_pair: key generation failed\n");
        return make_error(env, "Failed to generate key pair");
    }

    fprintf(stderr, "[NIF DEBUG] generate_identity_key_pair: key generation succeeded\n");

    fprintf(stderr, "[NIF DEBUG] generate_identity_key_pair: converting public key to binary\n");
    public_key = key_to_binary(env, key, 1);

    fprintf(stderr, "[NIF DEBUG] generate_identity_key_pair: converting private key to binary\n");
    private_key = key_to_binary(env, key, 0);

    EVP_PKEY_free(key);

    fprintf(stderr, "[NIF DEBUG] generate_identity_key_pair: returning result\n");
    return make_ok(env, enif_make_tuple2(env, public_key, private_key));
}

static ERL_NIF_TERM generate_pre_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    int key_id_signed;
    unsigned int key_id_unsigned;
    unsigned int key_id;
    EVP_PKEY *key;
    ERL_NIF_TERM public_key;

    fprintf(stderr, "[NIF DEBUG] generate_pre_key: argc=%d, argv[0]=%p\n", argc, argv[0]);

    if (enif_get_int(env, argv[0], &key_id_signed))
    {
        key_id = (unsigned int)key_id_signed;
        fprintf(stderr, "[NIF DEBUG] generate_pre_key: key_id (signed)=%d\n", key_id_signed);
    }
    else if (enif_get_uint(env, argv[0], &key_id_unsigned))
    {
        key_id = key_id_unsigned;
        fprintf(stderr, "[NIF DEBUG] generate_pre_key: key_id (unsigned)=%u\n", key_id_unsigned);
    }
    else
    {
        fprintf(stderr, "[NIF DEBUG] generate_pre_key: enif_get_int/uint failed\n");
        return make_error(env, "Invalid key ID");
    }

    if (!generate_ec_key_pair(&key))
    {
        return make_error(env, "Failed to generate pre-key");
    }

    public_key = key_to_binary(env, key, 1);
    EVP_PKEY_free(key);

    return make_ok(env, enif_make_tuple2(env, enif_make_uint(env, key_id), public_key));
}

static ERL_NIF_TERM generate_signed_pre_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary identity_key;
    int key_id;
    EVP_PKEY *key;
    ERL_NIF_TERM public_key, signature;

    if (!enif_inspect_binary(env, argv[0], &identity_key) ||
        !enif_get_int(env, argv[1], &key_id))
    {
        return make_error(env, "Invalid arguments");
    }

    fprintf(stderr, "[NIF DEBUG] generate_signed_pre_key: identity_key size=%zu\n", identity_key.size);
    fprintf(stderr, "[NIF DEBUG] generate_signed_pre_key: identity_key (hex): ");
    for (size_t i = 0; i < identity_key.size && i < 32; i++)
    {
        fprintf(stderr, "%02X ", identity_key.data[i]);
    }
    fprintf(stderr, "\n");

    if (!generate_ed25519_key_pair(&key))
    {
        return make_error(env, "Failed to generate signed pre-key");
    }

    public_key = key_to_binary(env, key, 1);
    signature = sign_data(env, key, identity_key.data, identity_key.size);

    // Debug: print the public key and signature
    ErlNifBinary pub_bin, sig_bin;
    if (enif_inspect_binary(env, public_key, &pub_bin))
    {
        fprintf(stderr, "[NIF DEBUG] generate_signed_pre_key: public_key size=%zu\n", pub_bin.size);
        fprintf(stderr, "[NIF DEBUG] generate_signed_pre_key: public_key (hex): ");
        for (size_t i = 0; i < pub_bin.size && i < 32; i++)
        {
            fprintf(stderr, "%02X ", pub_bin.data[i]);
        }
        fprintf(stderr, "\n");
    }

    if (enif_inspect_binary(env, signature, &sig_bin))
    {
        fprintf(stderr, "[NIF DEBUG] generate_signed_pre_key: signature size=%zu\n", sig_bin.size);
        fprintf(stderr, "[NIF DEBUG] generate_signed_pre_key: signature (hex): ");
        for (size_t i = 0; i < sig_bin.size && i < 64; i++)
        {
            fprintf(stderr, "%02X ", sig_bin.data[i]);
        }
        fprintf(stderr, "\n");
    }

    EVP_PKEY_free(key);
    return make_ok(env, enif_make_tuple3(env, enif_make_int(env, key_id), public_key, signature));
}

static ERL_NIF_TERM create_session(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argc;
    ErlNifBinary identity_key;
    ERL_NIF_TERM session_id;

    if (!enif_inspect_binary(env, argv[0], &identity_key))
    {
        return make_error(env, "Invalid identity key");
    }

    // Generate a unique session ID
    unsigned char id[32];
    if (!RAND_bytes(id, sizeof(id)))
    {
        return make_error(env, "Failed to generate session ID");
    }

    session_id = make_binary(env, id, sizeof(id));
    return make_ok(env, session_id);
}

static ERL_NIF_TERM process_pre_key_bundle(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary session, bundle;
    if (!enif_inspect_binary(env, argv[0], &session) ||
        !enif_inspect_binary(env, argv[1], &bundle))
    {
        return make_error(env, "Invalid arguments");
    }

    // Parse bundle components
    size_t offset = 0;
    uint32_t registration_id, device_id, pre_key_id, signed_pre_key_id;
    unsigned char *pre_key = NULL, *signed_pre_key = NULL, *identity_key = NULL;
    size_t pre_key_len = 0, signed_pre_key_len = 0, identity_key_len = 0;

    // Parse registration ID
    if (!parse_uint32(bundle.data + offset, &registration_id))
    {
        return make_error(env, "Invalid registration ID");
    }
    offset += 4;

    // Parse device ID
    if (!parse_uint32(bundle.data + offset, &device_id))
    {
        return make_error(env, "Invalid device ID");
    }
    offset += 4;

    // Parse pre-key ID
    if (!parse_uint32(bundle.data + offset, &pre_key_id))
    {
        return make_error(env, "Invalid pre-key ID");
    }
    offset += 4;

    // Parse pre-key
    if (!parse_binary(bundle.data, bundle.size, &offset, &pre_key, &pre_key_len))
    {
        return make_error(env, "Invalid pre-key");
    }

    // Parse signed pre-key ID
    if (!parse_uint32(bundle.data + offset, &signed_pre_key_id))
    {
        return make_error(env, "Invalid signed pre-key ID");
    }
    offset += 4;

    // Parse signed pre-key
    if (!parse_binary(bundle.data, bundle.size, &offset, &signed_pre_key, &signed_pre_key_len))
    {
        return make_error(env, "Invalid signed pre-key");
    }

    // Parse identity key
    if (!parse_binary(bundle.data, bundle.size, &offset, &identity_key, &identity_key_len))
    {
        return make_error(env, "Invalid identity key");
    }

    // Verify we've consumed all data
    if (offset != bundle.size)
    {
        return make_error(env, "Extra data in bundle");
    }

    // Create EVP_PKEY from pre-key
    EVP_PKEY *pre_key_ec = NULL;
    if (pre_key_len != CURVE25519_KEY_SIZE)
    {
        return make_error(env, "Invalid pre-key size");
    }
    pre_key_ec = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pre_key, pre_key_len);
    if (!pre_key_ec)
    {
        return make_error(env, "Failed to create pre-key EVP_PKEY");
    }

    // Create EVP_PKEY from signed pre-key
    EVP_PKEY *signed_pre_key_ec = NULL;
    if (signed_pre_key_len != CURVE25519_KEY_SIZE)
    {
        EVP_PKEY_free(pre_key_ec);
        return make_error(env, "Invalid signed pre-key size");
    }
    signed_pre_key_ec = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, signed_pre_key, signed_pre_key_len);
    if (!signed_pre_key_ec)
    {
        EVP_PKEY_free(pre_key_ec);
        return make_error(env, "Failed to create signed pre-key EVP_PKEY");
    }

    // Create EVP_PKEY from identity key
    EVP_PKEY *identity_key_ec = NULL;
    if (identity_key_len != CURVE25519_KEY_SIZE)
    {
        EVP_PKEY_free(signed_pre_key_ec);
        EVP_PKEY_free(pre_key_ec);
        return make_error(env, "Invalid identity key size");
    }
    identity_key_ec = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, identity_key, identity_key_len);
    if (!identity_key_ec)
    {
        EVP_PKEY_free(signed_pre_key_ec);
        EVP_PKEY_free(pre_key_ec);
        return make_error(env, "Failed to create identity key EVP_PKEY");
    }

    // Generate ephemeral key pair
    EVP_PKEY *ephemeral_key = NULL;
    if (!generate_ec_key_pair(&ephemeral_key))
    {
        EVP_PKEY_free(identity_key_ec);
        EVP_PKEY_free(signed_pre_key_ec);
        EVP_PKEY_free(pre_key_ec);
        return make_error(env, "Failed to generate ephemeral key");
    }

    // Calculate shared secrets
    unsigned char dh1[256], dh2[256], dh3[256];
    size_t dh1_len = sizeof(dh1), dh2_len = sizeof(dh2), dh3_len = sizeof(dh3);

    if (!calculate_dh_shared_secret(ephemeral_key, pre_key_ec, dh1, &dh1_len) ||
        !calculate_dh_shared_secret(ephemeral_key, signed_pre_key_ec, dh2, &dh2_len) ||
        !calculate_dh_shared_secret(ephemeral_key, identity_key_ec, dh3, &dh3_len))
    {
        EVP_PKEY_free(ephemeral_key);
        EVP_PKEY_free(identity_key_ec);
        EVP_PKEY_free(signed_pre_key_ec);
        EVP_PKEY_free(pre_key_ec);
        return make_error(env, "Failed to calculate shared secrets");
    }

    // Derive master secret
    unsigned char master_secret[96];
    memcpy(master_secret, dh1, dh1_len);
    memcpy(master_secret + dh1_len, dh2, dh2_len);
    memcpy(master_secret + dh1_len + dh2_len, dh3, dh3_len);

    // Derive root key
    unsigned char root_key[ROOT_KEY_LEN];
    if (!derive_root_key(master_secret, sizeof(master_secret), NULL, 0, root_key))
    {
        EVP_PKEY_free(ephemeral_key);
        EVP_PKEY_free(identity_key_ec);
        EVP_PKEY_free(signed_pre_key_ec);
        EVP_PKEY_free(pre_key_ec);
        return make_error(env, "Failed to derive root key");
    }

    // Derive chain key
    unsigned char chain_key[CHAIN_KEY_LEN];
    if (!derive_chain_key(root_key, ROOT_KEY_LEN, NULL, 0, chain_key))
    {
        EVP_PKEY_free(ephemeral_key);
        EVP_PKEY_free(identity_key_ec);
        EVP_PKEY_free(signed_pre_key_ec);
        EVP_PKEY_free(pre_key_ec);
        return make_error(env, "Failed to derive chain key");
    }

    // Create a simple session state without pointers
    simple_session_t session_state;
    memset(&session_state, 0, sizeof(simple_session_t));

    // Initialize session state with derived keys
    memcpy(session_state.root_key, root_key, ROOT_KEY_LEN);
    memcpy(session_state.sending_chain_key, chain_key, CHAIN_KEY_LEN);
    session_state.sending_chain_index = 0;
    session_state.sending_ratchet_index = 0;
    session_state.receiving_ratchet_index = 0;

    // Store ephemeral key as raw bytes
    size_t ephemeral_key_len = CURVE25519_KEY_SIZE;
    if (EVP_PKEY_get_raw_public_key(ephemeral_key, session_state.ephemeral_key, &ephemeral_key_len) <= 0)
    {
        EVP_PKEY_free(ephemeral_key);
        EVP_PKEY_free(identity_key_ec);
        EVP_PKEY_free(signed_pre_key_ec);
        EVP_PKEY_free(pre_key_ec);
        return make_error(env, "Failed to serialize ephemeral key");
    }

    // Serialize session state to binary
    ERL_NIF_TERM session_binary = make_binary(env, (unsigned char *)&session_state, sizeof(simple_session_t));

    // Clean up
    EVP_PKEY_free(ephemeral_key);
    EVP_PKEY_free(identity_key_ec);
    EVP_PKEY_free(signed_pre_key_ec);
    EVP_PKEY_free(pre_key_ec);

    return make_ok(env, session_binary);
}

static ERL_NIF_TERM encrypt_message(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argc;
    (void)argv;
    ErlNifBinary session, message;
    if (!enif_inspect_binary(env, argv[0], &session) ||
        !enif_inspect_binary(env, argv[1], &message))
    {
        return make_error(env, "Invalid arguments");
    }

    // Extract simple session state from session
    simple_session_t session_state;
    if (session.size < sizeof(simple_session_t))
    {
        return make_error(env, "Invalid session data");
    }
    memcpy(&session_state, session.data, sizeof(simple_session_t));

    // Create EVP_PKEY from ephemeral key
    EVP_PKEY *ephemeral_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                                          session_state.ephemeral_key, CURVE25519_KEY_SIZE);
    if (!ephemeral_key)
    {
        return make_error(env, "Failed to create ephemeral key");
    }

    // For now, just return a simple encrypted message
    // In a real implementation, this would do proper ratchet encryption
    unsigned char encrypted_data[message.size + 16]; // message + IV + tag
    memcpy(encrypted_data, message.data, message.size);

    // Add some padding to simulate encryption
    for (int i = 0; i < 16; i++)
    {
        encrypted_data[message.size + i] = i;
    }

    ERL_NIF_TERM encrypted = make_binary(env, encrypted_data, message.size + 16);
    EVP_PKEY_free(ephemeral_key);

    return make_ok(env, encrypted);
}

static ERL_NIF_TERM decrypt_message(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argc;
    (void)argv;
    ErlNifBinary session, encrypted;
    if (!enif_inspect_binary(env, argv[0], &session) ||
        !enif_inspect_binary(env, argv[1], &encrypted))
    {
        return make_error(env, "Invalid arguments");
    }

    if (encrypted.size < 16)
    { // Need at least some padding
        return make_error(env, "Invalid encrypted message");
    }

    // Extract simple session state from session
    simple_session_t session_state;
    if (session.size < sizeof(simple_session_t))
    {
        return make_error(env, "Invalid session data");
    }
    memcpy(&session_state, session.data, sizeof(simple_session_t));

    // For now, just return the original message (remove padding)
    // In a real implementation, this would do proper decryption
    size_t message_size = encrypted.size - 16;
    unsigned char decrypted_data[message_size];
    memcpy(decrypted_data, encrypted.data, message_size);

    ERL_NIF_TERM decrypted = make_binary(env, decrypted_data, message_size);

    return make_ok(env, decrypted);
}

// Cache statistics NIF functions
static ERL_NIF_TERM get_cache_stats(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argc;
    (void)argv;
    ErlNifBinary session;
    if (!enif_inspect_binary(env, argv[0], &session))
    {
        return make_error(env, "Invalid session data");
    }

    if (session.size < sizeof(ratchet_state_t))
    {
        return make_error(env, "Invalid session size");
    }

    ratchet_state_t *state = (ratchet_state_t *)session.data;

    // Create chain key cache stats map
    ERL_NIF_TERM chain_key_stats = enif_make_new_map(env);
    enif_make_map_put(env, chain_key_stats,
                      enif_make_atom(env, "hits"),
                      enif_make_ulong(env, state->chain_key_stats.hits),
                      &chain_key_stats);
    enif_make_map_put(env, chain_key_stats,
                      enif_make_atom(env, "misses"),
                      enif_make_ulong(env, state->chain_key_stats.misses),
                      &chain_key_stats);
    enif_make_map_put(env, chain_key_stats,
                      enif_make_atom(env, "hit_ratio"),
                      enif_make_double(env, state->chain_key_stats.hit_ratio),
                      &chain_key_stats);
    enif_make_map_put(env, chain_key_stats,
                      enif_make_atom(env, "current_size"),
                      enif_make_ulong(env, state->chain_key_stats.current_size),
                      &chain_key_stats);
    enif_make_map_put(env, chain_key_stats,
                      enif_make_atom(env, "max_size"),
                      enif_make_ulong(env, state->chain_key_stats.max_size),
                      &chain_key_stats);
    enif_make_map_put(env, chain_key_stats,
                      enif_make_atom(env, "cache_count"),
                      enif_make_ulong(env, state->chain_key_cache_count),
                      &chain_key_stats);

    // Create root key cache stats map
    ERL_NIF_TERM root_key_stats = enif_make_new_map(env);
    enif_make_map_put(env, root_key_stats,
                      enif_make_atom(env, "hits"),
                      enif_make_ulong(env, state->root_key_stats.hits),
                      &root_key_stats);
    enif_make_map_put(env, root_key_stats,
                      enif_make_atom(env, "misses"),
                      enif_make_ulong(env, state->root_key_stats.misses),
                      &root_key_stats);
    enif_make_map_put(env, root_key_stats,
                      enif_make_atom(env, "hit_ratio"),
                      enif_make_double(env, state->root_key_stats.hit_ratio),
                      &root_key_stats);
    enif_make_map_put(env, root_key_stats,
                      enif_make_atom(env, "current_size"),
                      enif_make_ulong(env, state->root_key_stats.current_size),
                      &root_key_stats);
    enif_make_map_put(env, root_key_stats,
                      enif_make_atom(env, "max_size"),
                      enif_make_ulong(env, state->root_key_stats.max_size),
                      &root_key_stats);
    enif_make_map_put(env, root_key_stats,
                      enif_make_atom(env, "cache_count"),
                      enif_make_ulong(env, state->root_key_cache_count),
                      &root_key_stats);

    // Create overall stats map
    ERL_NIF_TERM stats = enif_make_new_map(env);
    enif_make_map_put(env, stats,
                      enif_make_atom(env, "chain_key_cache"),
                      chain_key_stats,
                      &stats);
    enif_make_map_put(env, stats,
                      enif_make_atom(env, "root_key_cache"),
                      root_key_stats,
                      &stats);

    return make_ok(env, stats);
}

static ERL_NIF_TERM reset_cache_stats(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argc;
    (void)argv;
    ErlNifBinary session;
    if (!enif_inspect_binary(env, argv[0], &session))
    {
        return make_error(env, "Invalid session data");
    }

    if (session.size < sizeof(ratchet_state_t))
    {
        return make_error(env, "Invalid session size");
    }

    ratchet_state_t *state = (ratchet_state_t *)session.data;

    // Reset chain key cache stats
    state->chain_key_stats.hits = 0;
    state->chain_key_stats.misses = 0;
    state->chain_key_stats.hit_ratio = 0.0;
    state->chain_key_stats.last_adjustment = 0;

    // Reset root key cache stats
    state->root_key_stats.hits = 0;
    state->root_key_stats.misses = 0;
    state->root_key_stats.hit_ratio = 0.0;
    state->root_key_stats.last_adjustment = 0;

    return make_ok(env, enif_make_atom(env, "ok"));
}

static ERL_NIF_TERM set_cache_size(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    (void)argc;
    (void)argv;
    ErlNifBinary session;
    int cache_type;
    unsigned long new_size;
    if (!enif_inspect_binary(env, argv[0], &session) ||
        !enif_get_int(env, argv[1], &cache_type) ||
        !enif_get_ulong(env, argv[2], &new_size))
    {
        return make_error(env, "Invalid arguments");
    }

    if (session.size < sizeof(ratchet_state_t))
    {
        return make_error(env, "Invalid session size");
    }

    ratchet_state_t *state = (ratchet_state_t *)session.data;

    // Validate new size
    if (new_size < MIN_CHAIN_KEY_CACHE_SIZE || new_size > MAX_CHAIN_KEY_CACHE_SIZE)
    {
        return make_error(env, "Invalid cache size");
    }

    // Update cache size based on type
    if (cache_type == 0)
    { // Chain key cache
        if (new_size < state->chain_key_cache_count)
        {
            return make_error(env, "New size smaller than current cache count");
        }
        chain_key_cache_t *new_cache = OPENSSL_malloc(new_size * sizeof(chain_key_cache_t));
        if (!new_cache)
        {
            return make_error(env, "Failed to allocate new cache");
        }
        memcpy(new_cache, state->chain_key_cache,
               state->chain_key_cache_count * sizeof(chain_key_cache_t));
        OPENSSL_free(state->chain_key_cache);
        state->chain_key_cache = new_cache;
        state->chain_key_cache_size = new_size;
        state->chain_key_stats.current_size = new_size;
    }
    else if (cache_type == 1)
    { // Root key cache
        if (new_size < state->root_key_cache_count)
        {
            return make_error(env, "New size smaller than current cache count");
        }
        root_key_cache_t *new_cache = OPENSSL_malloc(new_size * sizeof(root_key_cache_t));
        if (!new_cache)
        {
            return make_error(env, "Failed to allocate new cache");
        }
        memcpy(new_cache, state->root_key_cache,
               state->root_key_cache_count * sizeof(root_key_cache_t));
        OPENSSL_free(state->root_key_cache);
        state->root_key_cache = new_cache;
        state->root_key_cache_size = new_size;
        state->root_key_stats.current_size = new_size;
    }
    else
    {
        return make_error(env, "Invalid cache type");
    }

    return make_ok(env, enif_make_atom(env, "ok"));
}

static ERL_NIF_TERM verify_signature(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 3)
    {
        return enif_make_badarg(env);
    }

    ErlNifBinary public_key_bin, data_bin, signature_bin;
    if (!enif_inspect_binary(env, argv[0], &public_key_bin) ||
        !enif_inspect_binary(env, argv[1], &data_bin) ||
        !enif_inspect_binary(env, argv[2], &signature_bin))
    {
        return enif_make_badarg(env);
    }

    // Create EVP_PKEY from public key
    EVP_PKEY *public_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                                       public_key_bin.data, public_key_bin.size);
    if (!public_key)
    {
        return make_error(env, "Failed to create public key");
    }

    // Verify signature using the crypto module
    crypto_error_t result = evp_verify_signature(public_key, data_bin.data, data_bin.size,
                                                 signature_bin.data, signature_bin.size);

    EVP_PKEY_free(public_key);

    if (result == CRYPTO_OK)
    {
        return make_ok(env, enif_make_atom(env, "true"));
    }
    else
    {
        return make_error(env, "invalid_signature");
    }
}

static ERL_NIF_TERM compute_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 4)
    {
        return enif_make_badarg(env);
    }

    // Parse algorithm and curve (we only support ecdh/curve25519)
    char algorithm[32], curve[32];
    if (!enif_get_atom(env, argv[0], algorithm, sizeof(algorithm), ERL_NIF_LATIN1) ||
        !enif_get_atom(env, argv[3], curve, sizeof(curve), ERL_NIF_LATIN1))
    {
        return enif_make_badarg(env);
    }

    if (strcmp(algorithm, "ecdh") != 0 || strcmp(curve, "curve25519") != 0)
    {
        return make_error(env, "unsupported_algorithm");
    }

    ErlNifBinary public_key_bin, private_key_bin;
    if (!enif_inspect_binary(env, argv[1], &public_key_bin) ||
        !enif_inspect_binary(env, argv[2], &private_key_bin))
    {
        return enif_make_badarg(env);
    }

    // Create EVP_PKEY objects
    EVP_PKEY *public_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                                       public_key_bin.data, public_key_bin.size);
    EVP_PKEY *private_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                         private_key_bin.data, private_key_bin.size);

    if (!public_key || !private_key)
    {
        if (public_key)
            EVP_PKEY_free(public_key);
        if (private_key)
            EVP_PKEY_free(private_key);
        return make_error(env, "Failed to create keys");
    }

    // Calculate shared secret
    uint8_t shared_secret[32];
    size_t shared_secret_len = sizeof(shared_secret);

    crypto_error_t result = calculate_dh_shared_secret(private_key, public_key,
                                                       shared_secret, &shared_secret_len);

    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);

    if (result == CRYPTO_OK)
    {
        return make_ok(env, make_binary(env, shared_secret, shared_secret_len));
    }
    else
    {
        return make_error(env, "Failed to compute shared secret");
    }
}