#include <erl_nif.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <sodium.h>

// Double Ratchet state structure
typedef struct {
    // Root chain key (32 bytes)
    unsigned char root_key[32];
    
    // Sending chain
    unsigned char send_chain_key[32];
    unsigned int send_message_number;
    
    // Receiving chain
    unsigned char recv_chain_key[32];
    unsigned int recv_message_number;
    
    // DH ratchet keys
    unsigned char dh_send_private[crypto_box_SECRETKEYBYTES];
    unsigned char dh_send_public[crypto_box_PUBLICKEYBYTES];
    unsigned char dh_recv_public[crypto_box_PUBLICKEYBYTES];
    
    // Previous sending chain length (for header)
    unsigned int prev_send_length;
    
    // Session established flag
    bool initialized;
} double_ratchet_state_t;

// Constants for Double Ratchet
#define DR_ROOT_KEY_SIZE 32
#define DR_CHAIN_KEY_SIZE 32
#define DR_MESSAGE_KEY_SIZE 32
#define DR_HEADER_KEY_SIZE 32
#define DR_STATE_SIZE sizeof(double_ratchet_state_t)

// HKDF-like key derivation using BLAKE2b
static int derive_keys(unsigned char *output, size_t output_len,
                      const unsigned char *input, size_t input_len,
                      const unsigned char *salt, size_t salt_len,
                      const unsigned char *info, size_t info_len) {
    // Use BLAKE2b with salt as key for HKDF-like derivation
    // If salt is provided, use it as the key, otherwise use input directly
    if (salt && salt_len > 0) {
        return crypto_generichash(output, output_len, input, input_len, salt, salt_len);
    } else {
        return crypto_generichash(output, output_len, input, input_len, NULL, 0);
    }
}

// Advance chain key using HMAC
static void advance_chain_key(unsigned char *chain_key, const unsigned char *current_key) {
    // Use HMAC with constant 0x01 to advance chain key
    unsigned char constant = 0x01;
    crypto_auth(chain_key, &constant, 1, current_key);
}

// Derive message key from chain key
static void derive_message_key(unsigned char *message_key, const unsigned char *chain_key) {
    // Use HMAC with constant 0x02 to derive message key
    unsigned char constant = 0x02;
    crypto_auth(message_key, &constant, 1, chain_key);
}

// Perform DH ratchet step
static int dh_ratchet(double_ratchet_state_t *state, const unsigned char *remote_public_key) {
    // Generate new DH key pair
    if (crypto_box_keypair(state->dh_send_public, state->dh_send_private) != 0) {
        return -1;
    }
    
    // Perform DH with remote public key
    unsigned char dh_output[crypto_box_BEFORENMBYTES];
    if (crypto_box_beforenm(dh_output, remote_public_key, state->dh_send_private) != 0) {
        return -1;
    }
    
    // Derive new root key and sending chain key
    unsigned char root_chain_input[64]; // root_key + dh_output
    memcpy(root_chain_input, state->root_key, 32);
    memcpy(root_chain_input + 32, dh_output, 32);
    
    unsigned char kdf_output[64]; // new_root_key + new_chain_key
    if (crypto_generichash(kdf_output, 64, root_chain_input, 64, NULL, 0) != 0) {
        sodium_memzero(dh_output, sizeof(dh_output));
        return -1;
    }
    
    // Update state
    memcpy(state->root_key, kdf_output, 32);
    memcpy(state->send_chain_key, kdf_output + 32, 32);
    memcpy(state->dh_recv_public, remote_public_key, crypto_box_PUBLICKEYBYTES);
    
    // Reset message counters
    state->prev_send_length = state->send_message_number;
    state->send_message_number = 0;
    
    // Clean up sensitive data
    sodium_memzero(dh_output, sizeof(dh_output));
    sodium_memzero(root_chain_input, sizeof(root_chain_input));
    sodium_memzero(kdf_output, sizeof(kdf_output));
    
    return 0;
}

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

// Generate identity key pair
static ERL_NIF_TERM generate_identity_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 0) {
        return enif_make_badarg(env);
    }
    
    // Generate Curve25519 key pair
    ERL_NIF_TERM public_key_term, private_key_term;
    unsigned char *public_key = enif_make_new_binary(env, crypto_box_PUBLICKEYBYTES, &public_key_term);
    unsigned char *private_key = enif_make_new_binary(env, crypto_box_SECRETKEYBYTES, &private_key_term);
    
    if (crypto_box_keypair(public_key, private_key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "key_generation_failed"));
    }
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple2(env, public_key_term, private_key_term));
}

// Generate pre-key
static ERL_NIF_TERM generate_pre_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 1) {
        return enif_make_badarg(env);
    }
    
    int key_id;
    if (!enif_get_int(env, argv[0], &key_id)) {
        return enif_make_badarg(env);
    }
    
    // Generate Curve25519 key pair
    ERL_NIF_TERM public_key_term;
    unsigned char *public_key = enif_make_new_binary(env, crypto_box_PUBLICKEYBYTES, &public_key_term);
    unsigned char private_key[crypto_box_SECRETKEYBYTES];
    
    if (crypto_box_keypair(public_key, private_key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "key_generation_failed"));
    }
    
    // Clear private key (not returned for pre-keys)
    sodium_memzero(private_key, sizeof(private_key));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple2(env, enif_make_int(env, key_id), public_key_term));
}

// Generate signed pre-key
static ERL_NIF_TERM generate_signed_pre_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary identity_private_key;
    int key_id;
    
    if (!enif_inspect_binary(env, argv[0], &identity_private_key) || 
        !enif_get_int(env, argv[1], &key_id)) {
        return enif_make_badarg(env);
    }
    
    // Validate identity key size
    if (identity_private_key.size != crypto_box_SECRETKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_identity_key_size"));
    }
    
    // Generate signed pre-key pair
    ERL_NIF_TERM public_key_term;
    unsigned char *public_key = enif_make_new_binary(env, crypto_box_PUBLICKEYBYTES, &public_key_term);
    unsigned char private_key[crypto_box_SECRETKEYBYTES];
    
    if (crypto_box_keypair(public_key, private_key) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "key_generation_failed"));
    }
    
    // Generate HMAC signature using identity private key
    ERL_NIF_TERM signature_term;
    unsigned char *signature = enif_make_new_binary(env, crypto_auth_BYTES, &signature_term);
    
    if (crypto_auth(signature, public_key, crypto_box_PUBLICKEYBYTES, identity_private_key.data) != 0) {
        sodium_memzero(private_key, sizeof(private_key));
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "signature_failed"));
    }
    
    // Clear private key
    sodium_memzero(private_key, sizeof(private_key));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple3(env, enif_make_int(env, key_id), 
                                          public_key_term, signature_term));
}

// Process X3DH pre-key bundle
static ERL_NIF_TERM process_pre_key_bundle(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary local_identity_private, bundle;
    
    if (!enif_inspect_binary(env, argv[0], &local_identity_private) ||
        !enif_inspect_binary(env, argv[1], &bundle)) {
        return enif_make_badarg(env);
    }
    
    // Validate input sizes
    if (local_identity_private.size != crypto_box_SECRETKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_identity_key_size"));
    }
    
    // Expected bundle format: identity_key(32) + signed_pre_key(32) + signature(32) + pre_key(32)
    if (bundle.size != 128) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_bundle_size"));
    }
    
    // Extract components from bundle
    unsigned char *remote_identity_public = bundle.data;
    unsigned char *signed_pre_key_public = bundle.data + 32;
    unsigned char *signature = bundle.data + 64;
    unsigned char *pre_key_public = bundle.data + 96;
    
    // Verify signed pre-key signature
    if (crypto_auth_verify(signature, signed_pre_key_public, crypto_box_PUBLICKEYBYTES, remote_identity_public) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "signature_verification_failed"));
    }
    
    // Generate ephemeral key pair for Alice
    ERL_NIF_TERM ephemeral_public_term;
    unsigned char *ephemeral_public = enif_make_new_binary(env, crypto_box_PUBLICKEYBYTES, &ephemeral_public_term);
    unsigned char ephemeral_private[crypto_box_SECRETKEYBYTES];
    
    if (crypto_box_keypair(ephemeral_public, ephemeral_private) != 0) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "ephemeral_key_generation_failed"));
    }
    
    // Perform X3DH key agreement (4 DH operations)
    unsigned char dh1[crypto_box_BEFORENMBYTES]; // Alice_identity * Bob_signed_pre_key
    unsigned char dh2[crypto_box_BEFORENMBYTES]; // Alice_ephemeral * Bob_identity
    unsigned char dh3[crypto_box_BEFORENMBYTES]; // Alice_ephemeral * Bob_signed_pre_key
    unsigned char dh4[crypto_box_BEFORENMBYTES]; // Alice_ephemeral * Bob_pre_key
    
    if (crypto_box_beforenm(dh1, signed_pre_key_public, local_identity_private.data) != 0 ||
        crypto_box_beforenm(dh2, remote_identity_public, ephemeral_private) != 0 ||
        crypto_box_beforenm(dh3, signed_pre_key_public, ephemeral_private) != 0 ||
        crypto_box_beforenm(dh4, pre_key_public, ephemeral_private) != 0) {
        
        sodium_memzero(ephemeral_private, sizeof(ephemeral_private));
        sodium_memzero(dh1, sizeof(dh1));
        sodium_memzero(dh2, sizeof(dh2));
        sodium_memzero(dh3, sizeof(dh3));
        sodium_memzero(dh4, sizeof(dh4));
        
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "key_agreement_failed"));
    }
    
    // Derive shared secret using HKDF-like construction
    unsigned char combined_dh[128]; // 4 * 32 bytes
    memcpy(combined_dh, dh1, 32);
    memcpy(combined_dh + 32, dh2, 32);
    memcpy(combined_dh + 64, dh3, 32);
    memcpy(combined_dh + 96, dh4, 32);
    
    ERL_NIF_TERM shared_secret_term;
    unsigned char *shared_secret = enif_make_new_binary(env, 64, &shared_secret_term);
    
    // Use BLAKE2b to derive 64-byte shared secret
    if (crypto_generichash(shared_secret, 64, combined_dh, 128, NULL, 0) != 0) {
        sodium_memzero(ephemeral_private, sizeof(ephemeral_private));
        sodium_memzero(dh1, sizeof(dh1));
        sodium_memzero(dh2, sizeof(dh2));
        sodium_memzero(dh3, sizeof(dh3));
        sodium_memzero(dh4, sizeof(dh4));
        sodium_memzero(combined_dh, sizeof(combined_dh));
        
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "key_derivation_failed"));
    }
    
    // Clear sensitive data
    sodium_memzero(ephemeral_private, sizeof(ephemeral_private));
    sodium_memzero(dh1, sizeof(dh1));
    sodium_memzero(dh2, sizeof(dh2));
    sodium_memzero(dh3, sizeof(dh3));
    sodium_memzero(dh4, sizeof(dh4));
    sodium_memzero(combined_dh, sizeof(combined_dh));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple2(env, shared_secret_term, ephemeral_public_term));
}

// Initialize Double Ratchet session from X3DH shared secret
static ERL_NIF_TERM init_double_ratchet(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 3) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary shared_secret, remote_public_key;
    int is_alice;
    
    if (!enif_inspect_binary(env, argv[0], &shared_secret) ||
        !enif_inspect_binary(env, argv[1], &remote_public_key) ||
        !enif_get_int(env, argv[2], &is_alice)) {
        return enif_make_badarg(env);
    }
    
    // Validate input sizes
    if (shared_secret.size != 64 || remote_public_key.size != crypto_box_PUBLICKEYBYTES) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_input_sizes"));
    }
    
    // Initialize Double Ratchet state
    double_ratchet_state_t state;
    memset(&state, 0, sizeof(state));
    
    // Initialize root key from shared secret (first 32 bytes)
    memcpy(state.root_key, shared_secret.data, 32);
    
    if (is_alice) {
        // Alice generates initial DH key pair and performs first ratchet
        if (crypto_box_keypair(state.dh_send_public, state.dh_send_private) != 0) {
            return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                                   enif_make_atom(env, "key_generation_failed"));
        }
        
        // Perform initial DH ratchet
        if (dh_ratchet(&state, remote_public_key.data) != 0) {
            return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                                   enif_make_atom(env, "dh_ratchet_failed"));
        }
        
        // Initialize receiving chain key from shared secret (last 32 bytes)
        memcpy(state.recv_chain_key, shared_secret.data + 32, 32);
    } else {
        // Bob stores Alice's public key and initializes sending chain
        memcpy(state.dh_recv_public, remote_public_key.data, crypto_box_PUBLICKEYBYTES);
        
        // Initialize sending chain key from shared secret (last 32 bytes)
        memcpy(state.send_chain_key, shared_secret.data + 32, 32);
        
        // Generate initial DH key pair (will be used when Bob first sends)
        if (crypto_box_keypair(state.dh_send_public, state.dh_send_private) != 0) {
            return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                                   enif_make_atom(env, "key_generation_failed"));
        }
    }
    
    // Initialize counters
    state.send_message_number = 0;
    state.recv_message_number = 0;
    state.prev_send_length = 0;
    state.initialized = true;
    
    // Create binary with the Double Ratchet state
    ERL_NIF_TERM dr_session_term;
    unsigned char *dr_session_data = enif_make_new_binary(env, DR_STATE_SIZE, &dr_session_term);
    memcpy(dr_session_data, &state, DR_STATE_SIZE);
    
    // Clear sensitive data from stack
    sodium_memzero(&state, sizeof(state));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), dr_session_term);
}

// Send message using Double Ratchet
static ERL_NIF_TERM dr_encrypt_message(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary dr_session, plaintext;
    
    if (!enif_inspect_binary(env, argv[0], &dr_session) ||
        !enif_inspect_binary(env, argv[1], &plaintext)) {
        return enif_make_badarg(env);
    }
    
    // Validate session size
    if (dr_session.size != DR_STATE_SIZE) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_session_size"));
    }
    
    // Copy state from binary
    double_ratchet_state_t state;
    memcpy(&state, dr_session.data, DR_STATE_SIZE);
    
    if (!state.initialized) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "session_not_initialized"));
    }
    
    // Derive message key from current chain key
    unsigned char message_key[DR_MESSAGE_KEY_SIZE];
    derive_message_key(message_key, state.send_chain_key);
    
    // Advance chain key
    advance_chain_key(state.send_chain_key, state.send_chain_key);
    
    // Create message header: DH_public_key(32) + prev_chain_length(4) + message_number(4)
    unsigned char header[40];
    memcpy(header, state.dh_send_public, 32);
    memcpy(header + 32, &state.prev_send_length, 4);
    memcpy(header + 36, &state.send_message_number, 4);
    
    // Generate nonce for message encryption
    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
    randombytes_buf(nonce, sizeof(nonce));
    
    // Calculate total message size: header(40) + nonce(12) + ciphertext + MAC
    size_t ciphertext_len = plaintext.size + crypto_aead_chacha20poly1305_ietf_ABYTES;
    size_t total_size = 40 + 12 + ciphertext_len;
    
    ERL_NIF_TERM encrypted_term;
    unsigned char *encrypted_data = enif_make_new_binary(env, total_size, &encrypted_term);
    
    // Store header and nonce
    memcpy(encrypted_data, header, 40);
    memcpy(encrypted_data + 40, nonce, 12);
    
    // Encrypt message
    unsigned long long actual_ciphertext_len;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            encrypted_data + 52, // After header and nonce
            &actual_ciphertext_len,
            plaintext.data, plaintext.size,
            header, 40,  // Use header as additional authenticated data
            NULL,        // No secret nonce
            nonce, message_key) != 0) {
        sodium_memzero(message_key, sizeof(message_key));
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "encryption_failed"));
    }
    
    // Increment message number
    state.send_message_number++;
    
    // Update session state
    ERL_NIF_TERM updated_session_term;
    unsigned char *updated_session_data = enif_make_new_binary(env, DR_STATE_SIZE, &updated_session_term);
    memcpy(updated_session_data, &state, DR_STATE_SIZE);
    
    // Clear sensitive data
    sodium_memzero(message_key, sizeof(message_key));
    sodium_memzero(&state, sizeof(state));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple2(env, encrypted_term, updated_session_term));
}

// Receive message using Double Ratchet
static ERL_NIF_TERM dr_decrypt_message(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
    if (argc != 2) {
        return enif_make_badarg(env);
    }
    
    ErlNifBinary dr_session, ciphertext;
    
    if (!enif_inspect_binary(env, argv[0], &dr_session) ||
        !enif_inspect_binary(env, argv[1], &ciphertext)) {
        return enif_make_badarg(env);
    }
    
    // Validate session size
    if (dr_session.size != DR_STATE_SIZE) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "invalid_session_size"));
    }
    
    // Validate minimum message size: header(40) + nonce(12) + MAC(16)
    if (ciphertext.size < 68) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "message_too_short"));
    }
    
    // Copy state from binary
    double_ratchet_state_t state;
    memcpy(&state, dr_session.data, DR_STATE_SIZE);
    
    if (!state.initialized) {
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "session_not_initialized"));
    }
    
    // Parse message header
    unsigned char *header = ciphertext.data;
    unsigned char *remote_dh_public = header;
    unsigned int prev_chain_length;
    unsigned int message_number;
    
    memcpy(&prev_chain_length, header + 32, 4);
    memcpy(&message_number, header + 36, 4);
    
    // Check if we need to perform DH ratchet (new DH public key)
    if (memcmp(remote_dh_public, state.dh_recv_public, crypto_box_PUBLICKEYBYTES) != 0) {
        // New DH public key - perform DH ratchet
        if (dh_ratchet(&state, remote_dh_public) != 0) {
            return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                                   enif_make_atom(env, "dh_ratchet_failed"));
        }
        
        // Initialize receiving chain key from new root key
        memcpy(state.recv_chain_key, state.root_key, 32);
        state.recv_message_number = 0;
    }
    
    // Advance receiving chain to the message number
    unsigned char temp_chain_key[32];
    memcpy(temp_chain_key, state.recv_chain_key, 32);
    
    for (unsigned int i = state.recv_message_number; i < message_number; i++) {
        advance_chain_key(temp_chain_key, temp_chain_key);
    }
    
    // Derive message key
    unsigned char message_key[DR_MESSAGE_KEY_SIZE];
    derive_message_key(message_key, temp_chain_key);
    
    // Extract nonce and encrypted data
    unsigned char *nonce = ciphertext.data + 40;
    unsigned char *encrypted_payload = ciphertext.data + 52;
    size_t encrypted_payload_len = ciphertext.size - 52;
    size_t plaintext_len = encrypted_payload_len - crypto_aead_chacha20poly1305_ietf_ABYTES;
    
    ERL_NIF_TERM decrypted_term;
    unsigned char *decrypted_data = enif_make_new_binary(env, plaintext_len, &decrypted_term);
    
    // Decrypt message
    unsigned long long actual_plaintext_len;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decrypted_data, &actual_plaintext_len,
            NULL,  // No secret nonce
            encrypted_payload, encrypted_payload_len,
            header, 40,  // Use header as additional authenticated data
            nonce, message_key) != 0) {
        sodium_memzero(message_key, sizeof(message_key));
        return enif_make_tuple2(env, enif_make_atom(env, "error"), 
                               enif_make_atom(env, "decryption_failed"));
    }
    
    // Update receiving chain state
    memcpy(state.recv_chain_key, temp_chain_key, 32);
    advance_chain_key(state.recv_chain_key, state.recv_chain_key);
    state.recv_message_number = message_number + 1;
    
    // Update session state
    ERL_NIF_TERM updated_session_term;
    unsigned char *updated_session_data = enif_make_new_binary(env, DR_STATE_SIZE, &updated_session_term);
    memcpy(updated_session_data, &state, DR_STATE_SIZE);
    
    // Clear sensitive data
    sodium_memzero(message_key, sizeof(message_key));
    sodium_memzero(temp_chain_key, sizeof(temp_chain_key));
    sodium_memzero(&state, sizeof(state));
    
    return enif_make_tuple2(env, enif_make_atom(env, "ok"), 
                           enif_make_tuple2(env, decrypted_term, updated_session_term));
}

// Define the NIF function array with proper Double Ratchet function names
static ErlNifFunc nif_funcs[] = {
    {"init", 0, init_nif, 0},
    {"generate_identity_key_pair", 0, generate_identity_key_pair, 0},
    {"generate_pre_key", 1, generate_pre_key, 0},
    {"generate_signed_pre_key", 2, generate_signed_pre_key, 0},
    {"process_pre_key_bundle", 2, process_pre_key_bundle, 0},
    {"init_double_ratchet", 3, init_double_ratchet, 0},
    {"dr_encrypt_message", 2, dr_encrypt_message, 0},
    {"dr_decrypt_message", 2, dr_decrypt_message, 0}
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
ERL_NIF_INIT(libsignal_protocol_nif_v2, nif_funcs, on_load, NULL, NULL, on_unload) 