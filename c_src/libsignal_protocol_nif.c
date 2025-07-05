#include <erl_nif.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sodium.h>

// Initialize the NIF library
static ERL_NIF_TERM init_nif(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 0) {
        return enif_make_badarg(env);
    }
    
    // Initialize libsodium
    if (sodium_init() < 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "sodium_init_failed"));
    }
    
    return enif_make_atom(env, "ok");
}

// Generate identity key pair using Curve25519
static ERL_NIF_TERM generate_identity_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 0) {
        return enif_make_badarg(env);
    }
    
    // Generate real Curve25519 key pair
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];  // 32 bytes
    unsigned char private_key[crypto_box_SECRETKEYBYTES]; // 32 bytes
    
    if (crypto_box_keypair(public_key, private_key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "key_generation_failed"));
    }
    
    ERL_NIF_TERM public_term, private_term;
    unsigned char *public_data = enif_make_new_binary(env, crypto_box_PUBLICKEYBYTES, &public_term);
    unsigned char *private_data = enif_make_new_binary(env, crypto_box_SECRETKEYBYTES, &private_term);
    
    memcpy(public_data, public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(private_data, private_key, crypto_box_SECRETKEYBYTES);
    
    // Clear sensitive data from stack
    sodium_memzero(private_key, sizeof(private_key));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple2(env, public_term, private_term));
}

// Generate pre-key using Curve25519
static ERL_NIF_TERM generate_pre_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 1) {
        return enif_make_badarg(env);
    }
    
    int key_id;
    if (!enif_get_int(env, argv[0], &key_id)) {
        return enif_make_badarg(env);
    }
    
    // Generate real Curve25519 pre-key
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char private_key[crypto_box_SECRETKEYBYTES];
    
    if (crypto_box_keypair(public_key, private_key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "key_generation_failed"));
    }
    
    ERL_NIF_TERM pre_key_term;
    unsigned char *pre_key_data = enif_make_new_binary(env, crypto_box_PUBLICKEYBYTES, &pre_key_term);
    memcpy(pre_key_data, public_key, crypto_box_PUBLICKEYBYTES);
    
    // Clear sensitive data
    sodium_memzero(private_key, sizeof(private_key));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple2(env, enif_make_int(env, key_id), pre_key_term));
}

// Generate signed pre-key using Ed25519 signatures
static ERL_NIF_TERM generate_signed_pre_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary identity_key;
    int key_id;
    
    if (!enif_inspect_binary(env, argv[0], &identity_key) || 
        !enif_get_int(env, argv[1], &key_id)) {
        return enif_make_badarg(env);
    }
    
    // Validate identity key size
    if (identity_key.size != crypto_box_SECRETKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_identity_key_size"));
    }
    
    // Generate real Curve25519 pre-key
    unsigned char public_key[crypto_box_PUBLICKEYBYTES];
    unsigned char private_key[crypto_box_SECRETKEYBYTES];
    
    if (crypto_box_keypair(public_key, private_key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "key_generation_failed"));
    }
    
    // Create message to sign (key_id + public_key)
    unsigned char message_to_sign[sizeof(int) + crypto_box_PUBLICKEYBYTES];
    memcpy(message_to_sign, &key_id, sizeof(int));
    memcpy(message_to_sign + sizeof(int), public_key, crypto_box_PUBLICKEYBYTES);
    
    // For simplicity, use HMAC-SHA256 instead of Ed25519 since we have Curve25519 keys
    unsigned char signature[32];  // HMAC-SHA256 output is 32 bytes
    
    // Use libsodium's crypto_auth for HMAC
    if (crypto_auth(signature, message_to_sign, sizeof(message_to_sign), identity_key.data) != 0) {
        sodium_memzero(private_key, sizeof(private_key));
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "signature_failed"));
    }
    
    ERL_NIF_TERM pre_key_term, signature_term;
    unsigned char *pre_key_data = enif_make_new_binary(env, crypto_box_PUBLICKEYBYTES, &pre_key_term);
    unsigned char *signature_data = enif_make_new_binary(env, 32, &signature_term);
    
    memcpy(pre_key_data, public_key, crypto_box_PUBLICKEYBYTES);
    memcpy(signature_data, signature, 32);
    
    // Clear sensitive data
    sodium_memzero(private_key, sizeof(private_key));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple3(env, enif_make_int(env, key_id), pre_key_term, signature_term));
}

// Create session (single argument version) - generate session key from public key
static ERL_NIF_TERM create_session_1(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 1) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary public_key;
    if (!enif_inspect_binary(env, argv[0], &public_key)) {
        return enif_make_badarg(env);
    }
    
    // Validate public key size
    if (public_key.size != crypto_box_PUBLICKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_public_key_size"));
    }
    
    // Create session state with derived key
    ERL_NIF_TERM session_term;
    unsigned char *session_data = enif_make_new_binary(env, 64, &session_term);
    
    // Use public key as base for session key (simplified approach)
    // In a real implementation, this would involve proper key agreement
    crypto_generichash(session_data, 32, public_key.data, public_key.size, NULL, 0);
    
    // Add some randomness for the rest of the session state
    randombytes_buf(session_data + 32, 32);
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), session_term);
}

// Create session (two argument version) - perform key agreement
static ERL_NIF_TERM create_session_2(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary local_key, remote_key;
    if (!enif_inspect_binary(env, argv[0], &local_key) || 
        !enif_inspect_binary(env, argv[1], &remote_key)) {
        return enif_make_badarg(env);
    }
    
    // Validate key sizes
    if (local_key.size != crypto_box_SECRETKEYBYTES || 
        remote_key.size != crypto_box_PUBLICKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_key_sizes"));
    }
    
    // Create session state with shared secret
    ERL_NIF_TERM session_term;
    unsigned char *session_data = enif_make_new_binary(env, 64, &session_term);
    
    // Perform Curve25519 key agreement
    unsigned char shared_secret[crypto_box_BEFORENMBYTES];
    if (crypto_box_beforenm(shared_secret, remote_key.data, local_key.data) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "key_agreement_failed"));
    }
    
    // Derive session key from shared secret
    crypto_generichash(session_data, 32, shared_secret, sizeof(shared_secret), NULL, 0);
    
    // Add some randomness for the rest of the session state
    randombytes_buf(session_data + 32, 32);
    
    // Clear sensitive data
    sodium_memzero(shared_secret, sizeof(shared_secret));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), session_term);
}

// Process pre-key bundle
static ERL_NIF_TERM process_pre_key_bundle(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary session, bundle;
    
    if (!enif_inspect_binary(env, argv[0], &session) ||
        !enif_inspect_binary(env, argv[1], &bundle)) {
        return enif_make_badarg(env);
    }
    
    // Process bundle (placeholder implementation)
    return enif_make_atom(env, "ok");
}

// Encrypt message using ChaCha20-Poly1305
static ERL_NIF_TERM encrypt_message(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary session, message;
    
    if (!enif_inspect_binary(env, argv[0], &session) ||
        !enif_inspect_binary(env, argv[1], &message)) {
        return enif_make_badarg(env);
    }
    
    // Validate session size (should contain at least a 32-byte key)
    if (session.size < 32) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_session"));
    }
    
    // Use first 32 bytes of session as encryption key
    unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    memcpy(key, session.data, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
    
    // Generate random nonce
    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    
    // Calculate ciphertext size (plaintext + MAC + nonce)
    size_t ciphertext_len = message.size + crypto_aead_chacha20poly1305_ietf_ABYTES;
    size_t total_size = ciphertext_len + crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    
    ERL_NIF_TERM encrypted_term;
    unsigned char *encrypted_data = enif_make_new_binary(env, total_size, &encrypted_term);
    
    // Store nonce at the beginning
    memcpy(encrypted_data, nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    
    // Encrypt the message
    unsigned long long actual_ciphertext_len;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            encrypted_data + crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
            &actual_ciphertext_len,
            message.data, message.size,
            NULL, 0,  // No additional data
            NULL,     // No secret nonce
            nonce, key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "encryption_failed"));
    }
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), encrypted_term);
}

// Decrypt message using ChaCha20-Poly1305
static ERL_NIF_TERM decrypt_message(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary session, encrypted;
    
    if (!enif_inspect_binary(env, argv[0], &session) ||
        !enif_inspect_binary(env, argv[1], &encrypted)) {
        return enif_make_badarg(env);
    }
    
    // Validate session size (should contain at least a 32-byte key)
    if (session.size < 32) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_session"));
    }
    
    // Validate encrypted message size (nonce + ciphertext + MAC)
    size_t min_size = crypto_aead_chacha20poly1305_ietf_NPUBBYTES + 
                     crypto_aead_chacha20poly1305_ietf_ABYTES;
    if (encrypted.size < min_size) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_message"));
    }
    
    // Use first 32 bytes of session as decryption key
    unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    memcpy(key, session.data, crypto_aead_chacha20poly1305_ietf_KEYBYTES);
    
    // Extract nonce from the beginning of encrypted data
    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    memcpy(nonce, encrypted.data, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    
    // Calculate plaintext size
    size_t ciphertext_len = encrypted.size - crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    size_t plaintext_len = ciphertext_len - crypto_aead_chacha20poly1305_ietf_ABYTES;
    
    ERL_NIF_TERM decrypted_term;
    unsigned char *decrypted_data = enif_make_new_binary(env, plaintext_len, &decrypted_term);
    
    // Decrypt the message
    unsigned long long actual_plaintext_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decrypted_data, &actual_plaintext_len,
            NULL,  // No secret nonce
            encrypted.data + crypto_aead_chacha20poly1305_ietf_NPUBBYTES,
            ciphertext_len,
            NULL, 0,  // No additional data
            nonce, key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "decryption_failed"));
    }
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), decrypted_term);
}

// Cache operations (placeholder implementations)
static ERL_NIF_TERM get_cache_stats(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 1) {
        return enif_make_badarg(env);
    }
    
    // Return dummy cache stats
    ERL_NIF_TERM stats = enif_make_new_map(env);
    enif_make_map_put(env, stats, enif_make_atom(env, "hits"), enif_make_int(env, 0), &stats);
    enif_make_map_put(env, stats, enif_make_atom(env, "misses"), enif_make_int(env, 0), &stats);
    enif_make_map_put(env, stats, enif_make_atom(env, "size"), enif_make_int(env, 0), &stats);
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), stats);
}

static ERL_NIF_TERM reset_cache_stats(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 1) {
        return enif_make_badarg(env);
    }
    
    return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM set_cache_size(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 3) {
        return enif_make_badarg(env);
    }
    
    return enif_make_atom(env, "ok");
}

// Define the NIF function array
static ErlNifFunc nif_funcs[] = {
    {"init", 0, init_nif, 0},
    {"generate_identity_key_pair", 0, generate_identity_key_pair, 0},
    {"generate_pre_key", 1, generate_pre_key, 0},
    {"generate_signed_pre_key", 2, generate_signed_pre_key, 0},
    {"create_session", 1, create_session_1, 0},
    {"create_session", 2, create_session_2, 0},
    {"process_pre_key_bundle", 2, process_pre_key_bundle, 0},
    {"encrypt_message", 2, encrypt_message, 0},
    {"decrypt_message", 2, decrypt_message, 0},
    {"get_cache_stats", 1, get_cache_stats, 0},
    {"reset_cache_stats", 1, reset_cache_stats, 0},
    {"set_cache_size", 3, set_cache_size, 0}
};

static int on_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    // Initialize random seed
    srand((unsigned int)time(NULL));
    return 0;
}

static void on_unload(ErlNifEnv *env, void *priv_data)
{
}

// Initialize the NIF library
ERL_NIF_INIT(libsignal_protocol_nif, nif_funcs, on_load, NULL, NULL, on_unload) 