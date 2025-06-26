#include "protocol.h"
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include "../crypto/crypto.h"

// Helper functions for key derivation
static protocol_error_t derive_chain_key(uint8_t *chain_key, size_t chain_key_len,
                                         const uint8_t *input_key, size_t input_key_len,
                                         const char *label)
{
    if (!chain_key || !input_key || !label)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    // Use HKDF to derive the chain key
    uint8_t info[32];
    size_t info_len = strlen(label);
    if (info_len > sizeof(info))
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }
    memcpy(info, label, info_len);

    uint8_t salt[32] = {0}; // Zero salt for chain key derivation
    if (!HMAC(EVP_sha256(), salt, sizeof(salt),
              input_key, input_key_len,
              chain_key, (unsigned int *)&chain_key_len))
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    return PROTOCOL_OK;
}

static protocol_error_t derive_message_key(uint8_t *message_key, size_t message_key_len,
                                           const uint8_t *chain_key, size_t chain_key_len)
{
    return derive_chain_key(message_key, message_key_len,
                            chain_key, chain_key_len,
                            "MessageKey");
}

// Advanced key derivation functions
protocol_error_t protocol_derive_root_key(const unsigned char *dh_output, size_t dh_output_len,
                                          const unsigned char *salt, size_t salt_len,
                                          unsigned char *root_key)
{
    if (!dh_output || !root_key)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

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
        return PROTOCOL_ERROR_INTERNAL;
    }

    // Use the HMAC result as the root key
    memcpy(root_key, hmac_result, ROOT_KEY_LEN);
    return PROTOCOL_OK;
}

protocol_error_t protocol_derive_chain_key(const unsigned char *root_key, size_t root_key_len,
                                           const unsigned char *salt, size_t salt_len,
                                           unsigned char *chain_key)
{
    if (!root_key || !chain_key)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

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
        return PROTOCOL_ERROR_INTERNAL;
    }

    // Use the HMAC result as the chain key
    memcpy(chain_key, hmac_result, CHAIN_KEY_LEN);
    return PROTOCOL_OK;
}

protocol_error_t protocol_derive_message_key(const unsigned char *chain_key, size_t chain_key_len,
                                             const unsigned char *salt, size_t salt_len,
                                             unsigned char *message_key)
{
    if (!chain_key || !message_key)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

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
        return PROTOCOL_ERROR_INTERNAL;
    }

    // Use the HMAC result as the message key
    memcpy(message_key, hmac_result, MESSAGE_KEY_LEN);
    return PROTOCOL_OK;
}

// DH shared secret calculation
protocol_error_t protocol_calculate_dh_shared_secret(EVP_PKEY *our_key, EVP_PKEY *their_key,
                                                     unsigned char *shared_secret, size_t *shared_secret_len)
{
    if (!our_key || !their_key || !shared_secret || !shared_secret_len)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(our_key, NULL);
    if (!ctx)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return PROTOCOL_ERROR_INTERNAL;
    }

    if (EVP_PKEY_derive_set_peer(ctx, their_key) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return PROTOCOL_ERROR_INTERNAL;
    }

    if (EVP_PKEY_derive(ctx, shared_secret, shared_secret_len) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return PROTOCOL_ERROR_INTERNAL;
    }

    EVP_PKEY_CTX_free(ctx);
    return PROTOCOL_OK;
}

// Bundle parsing helper functions
protocol_error_t protocol_parse_uint32(const unsigned char *data, uint32_t *value)
{
    if (!data || !value)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }
    *value = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    return PROTOCOL_OK;
}

protocol_error_t protocol_parse_binary(const unsigned char *data, size_t data_len, size_t *offset,
                                       unsigned char **binary, size_t *binary_len)
{
    if (!data || !offset || !binary || !binary_len || *offset + 4 > data_len)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    uint32_t len;
    if (protocol_parse_uint32(data + *offset, &len) != PROTOCOL_OK)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }
    *offset += 4;

    if (*offset + len > data_len)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    *binary = (unsigned char *)data + *offset;
    *binary_len = len;
    *offset += len;
    return PROTOCOL_OK;
}

// Advanced ratchet functions
protocol_error_t protocol_ratchet_state_create(protocol_ratchet_state_t **state)
{
    if (!state)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    *state = calloc(1, sizeof(protocol_ratchet_state_t));
    if (!*state)
    {
        return PROTOCOL_ERROR_MEMORY;
    }

    return PROTOCOL_OK;
}

void protocol_ratchet_state_destroy(protocol_ratchet_state_t *state)
{
    if (!state)
    {
        return;
    }

    // Clean up EVP_PKEY objects
    if (state->sending_chain.dh_key)
    {
        EVP_PKEY_free(state->sending_chain.dh_key);
    }
    if (state->receiving_chain.dh_key)
    {
        EVP_PKEY_free(state->receiving_chain.dh_key);
    }

    // Secure zero the memory
    crypto_secure_zero(state, sizeof(protocol_ratchet_state_t));
    free(state);
}

// Ratchet chain management
protocol_error_t protocol_rotate_chain_key(protocol_ratchet_chain_t *chain)
{
    if (!chain)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    // Check if we can use cached chain key
    if (chain->chain_index + 1 < RATCHET_ROTATION_THRESHOLD)
    {
        unsigned char new_chain_key[CHAIN_KEY_LEN];
        const unsigned char salt[] = "ChainKey";
        if (protocol_derive_chain_key(chain->chain_key, CHAIN_KEY_LEN,
                                      salt, sizeof(salt), new_chain_key) != PROTOCOL_OK)
        {
            return PROTOCOL_ERROR_INTERNAL;
        }
        memcpy(chain->chain_key, new_chain_key, CHAIN_KEY_LEN);
        chain->chain_index++;
        return PROTOCOL_OK;
    }
    return PROTOCOL_ERROR_INTERNAL;
}

protocol_error_t protocol_add_message_key(protocol_ratchet_chain_t *chain, const unsigned char *message_key)
{
    if (!chain || !message_key)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    if (chain->message_key_count >= MAX_MESSAGE_KEYS)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    memcpy(chain->message_keys[chain->message_key_count].key, message_key, MESSAGE_KEY_LEN);
    chain->message_keys[chain->message_key_count].index = chain->chain_index;
    chain->message_keys[chain->message_key_count].ratchet_index = chain->chain_index;
    chain->message_key_count++;

    // Cleanup if we're approaching the limit
    if (chain->message_key_count >= MESSAGE_KEY_CLEANUP_THRESHOLD)
    {
        protocol_cleanup_message_keys(chain);
    }

    return PROTOCOL_OK;
}

protocol_error_t protocol_rotate_sending_ratchet(protocol_ratchet_state_t *state)
{
    if (!state)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    // Generate new DH key pair
    EVP_PKEY *new_dh_key = NULL;
    crypto_error_t result = evp_generate_ec_keypair(NULL, &new_dh_key);
    if (result != CRYPTO_OK || !new_dh_key)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    // Calculate new shared secret
    unsigned char shared_secret[32];
    size_t shared_secret_len = sizeof(shared_secret);
    if (protocol_calculate_dh_shared_secret(new_dh_key, state->receiving_chain.dh_key,
                                            shared_secret, &shared_secret_len) != PROTOCOL_OK)
    {
        EVP_PKEY_free(new_dh_key);
        return PROTOCOL_ERROR_INTERNAL;
    }

    // Derive new root key
    unsigned char new_root_key[ROOT_KEY_LEN];
    if (protocol_derive_root_key(shared_secret, shared_secret_len,
                                 NULL, 0, new_root_key) != PROTOCOL_OK)
    {
        EVP_PKEY_free(new_dh_key);
        return PROTOCOL_ERROR_INTERNAL;
    }

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

    return PROTOCOL_OK;
}

protocol_error_t protocol_rotate_receiving_ratchet(protocol_ratchet_state_t *state, EVP_PKEY *their_dh_key)
{
    if (!state || !their_dh_key)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    // Generate new DH key pair
    EVP_PKEY *new_dh_key = NULL;
    crypto_error_t result = evp_generate_ec_keypair(NULL, &new_dh_key);
    if (result != CRYPTO_OK || !new_dh_key)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    // Calculate new shared secret
    unsigned char shared_secret[32];
    size_t shared_secret_len = sizeof(shared_secret);
    if (protocol_calculate_dh_shared_secret(new_dh_key, their_dh_key,
                                            shared_secret, &shared_secret_len) != PROTOCOL_OK)
    {
        EVP_PKEY_free(new_dh_key);
        return PROTOCOL_ERROR_INTERNAL;
    }

    // Derive new root key
    unsigned char new_root_key[ROOT_KEY_LEN];
    if (protocol_derive_root_key(shared_secret, shared_secret_len,
                                 NULL, 0, new_root_key) != PROTOCOL_OK)
    {
        EVP_PKEY_free(new_dh_key);
        return PROTOCOL_ERROR_INTERNAL;
    }

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

    return PROTOCOL_OK;
}

// Message key management
void protocol_cleanup_message_keys(protocol_ratchet_chain_t *chain)
{
    if (!chain)
    {
        return;
    }

    // Remove old message keys (keep only the most recent ones)
    size_t keep_count = MAX_MESSAGE_KEYS / 2;
    if (chain->message_key_count > keep_count)
    {
        size_t remove_count = chain->message_key_count - keep_count;
        memmove(&chain->message_keys[0], &chain->message_keys[remove_count],
                keep_count * sizeof(protocol_message_key_t));
        chain->message_key_count = keep_count;
    }
}

void protocol_cleanup_skip_keys(protocol_ratchet_chain_t *chain)
{
    if (!chain)
    {
        return;
    }

    // Remove old skip keys (keep only the most recent ones)
    size_t keep_count = MAX_SKIP_KEYS / 2;
    if (chain->skip_key_count > keep_count)
    {
        size_t remove_count = chain->skip_key_count - keep_count;
        memmove(&chain->skip_keys[0], &chain->skip_keys[remove_count],
                keep_count * sizeof(protocol_message_key_t));
        chain->skip_key_count = keep_count;
    }
}

void protocol_cleanup_ratchet_state(protocol_ratchet_state_t *state)
{
    if (!state)
    {
        return;
    }

    protocol_cleanup_message_keys(&state->sending_chain);
    protocol_cleanup_message_keys(&state->receiving_chain);
    protocol_cleanup_skip_keys(&state->sending_chain);
    protocol_cleanup_skip_keys(&state->receiving_chain);
}

// Protocol store management
protocol_error_t protocol_protocol_store_create(protocol_protocol_store_t **store)
{
    if (!store)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    *store = calloc(1, sizeof(protocol_protocol_store_t));
    if (!*store)
    {
        return PROTOCOL_ERROR_MEMORY;
    }

    return PROTOCOL_OK;
}

void protocol_protocol_store_destroy(protocol_protocol_store_t *store)
{
    if (store)
    {
        if (store->pre_keys)
        {
            free(store->pre_keys);
        }
        if (store->signed_pre_keys)
        {
            free(store->signed_pre_keys);
        }
        free(store);
    }
}

// Session management
protocol_error_t protocol_session_create(protocol_session_state_t **session,
                                         const protocol_protocol_store_t *store,
                                         const protocol_identity_key_t *local_identity_key,
                                         const protocol_identity_key_t *remote_identity_key)
{
    if (!session || !store || !local_identity_key || !remote_identity_key)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    *session = calloc(1, sizeof(protocol_session_state_t));
    if (!*session)
    {
        return PROTOCOL_ERROR_MEMORY;
    }

    (*session)->session_version = PROTOCOL_VERSION;
    (*session)->local_registration_id = store->registration_id;
    memcpy(&(*session)->local_identity_key, local_identity_key, sizeof(protocol_identity_key_t));
    memcpy(&(*session)->remote_identity_key, remote_identity_key, sizeof(protocol_identity_key_t));

    // Initialize chain keys with random values
    if (crypto_random_bytes((*session)->sender_chain_key, PROTOCOL_SESSION_KEY_SIZE) != CRYPTO_OK ||
        crypto_random_bytes((*session)->receiver_chain_key, PROTOCOL_SESSION_KEY_SIZE) != CRYPTO_OK ||
        crypto_random_bytes((*session)->root_key, PROTOCOL_SESSION_KEY_SIZE) != CRYPTO_OK)
    {
        free(*session);
        return PROTOCOL_ERROR_INTERNAL;
    }

    return PROTOCOL_OK;
}

void protocol_session_destroy(protocol_session_state_t *session)
{
    if (session)
    {
        crypto_secure_zero(session, sizeof(protocol_session_state_t));
        free(session);
    }
}

// Message processing
protocol_error_t protocol_process_pre_key_bundle(protocol_session_state_t *session,
                                                 const protocol_pre_key_bundle_t *bundle)
{
    if (!session || !bundle)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    if (bundle->version != PROTOCOL_VERSION)
    {
        return PROTOCOL_ERROR_INVALID_VERSION;
    }

    // Verify the identity key
    if (protocol_verify_identity_key(&bundle->identity_key) != PROTOCOL_OK)
    {
        return PROTOCOL_ERROR_INVALID_KEY;
    }

    // Store the remote registration ID
    session->remote_registration_id = bundle->registration_id;

    // Perform the X3DH key agreement
    uint8_t shared_secret[32];
    size_t shared_secret_len;

    // 1. DH(identity_key, base_key)
    if (curve25519_shared_secret(&session->local_identity_key.key,
                                 &bundle->base_key.key,
                                 shared_secret, &shared_secret_len) != CRYPTO_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    // 2. DH(ephemeral_key, identity_key)
    uint8_t shared_secret2[32];
    size_t shared_secret2_len;
    if (curve25519_shared_secret(&session->local_identity_key.key,
                                 &bundle->identity_key.key,
                                 shared_secret2, &shared_secret2_len) != CRYPTO_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    // 3. DH(ephemeral_key, base_key)
    uint8_t shared_secret3[32];
    size_t shared_secret3_len;
    if (curve25519_shared_secret(&session->local_identity_key.key,
                                 &bundle->base_key.key,
                                 shared_secret3, &shared_secret3_len) != CRYPTO_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    // Combine the shared secrets
    uint8_t combined_secret[96];
    memcpy(combined_secret, shared_secret, 32);
    memcpy(combined_secret + 32, shared_secret2, 32);
    memcpy(combined_secret + 64, shared_secret3, 32);

    // Derive the root key and chain keys
    if (derive_chain_key(session->root_key, PROTOCOL_SESSION_KEY_SIZE,
                         combined_secret, sizeof(combined_secret),
                         "RootKey") != PROTOCOL_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    if (derive_chain_key(session->sender_chain_key, PROTOCOL_SESSION_KEY_SIZE,
                         session->root_key, PROTOCOL_SESSION_KEY_SIZE,
                         "SenderChainKey") != PROTOCOL_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    if (derive_chain_key(session->receiver_chain_key, PROTOCOL_SESSION_KEY_SIZE,
                         session->root_key, PROTOCOL_SESSION_KEY_SIZE,
                         "ReceiverChainKey") != PROTOCOL_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    return PROTOCOL_OK;
}

protocol_error_t protocol_encrypt_message(protocol_session_state_t *session,
                                          const uint8_t *message, size_t message_len,
                                          uint8_t *ciphertext, size_t *ciphertext_len)
{
    if (!session || !message || !ciphertext || !ciphertext_len)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    // Generate a new ephemeral key pair
    curve25519_key_t ephemeral_key;
    if (curve25519_generate_keypair(&ephemeral_key, NULL) != CRYPTO_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    // Derive the message key
    uint8_t message_key[32];
    if (derive_message_key(message_key, sizeof(message_key),
                           session->sender_chain_key, PROTOCOL_SESSION_KEY_SIZE) != PROTOCOL_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    // Encrypt the message
    uint8_t iv[12];
    if (crypto_random_bytes(iv, sizeof(iv)) != CRYPTO_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    size_t encrypted_len = message_len + 16; // Message + MAC
    if (*ciphertext_len < encrypted_len)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    if (aes_gcm_encrypt((aes_key_t *)message_key, iv, sizeof(iv),
                        message, message_len,
                        NULL, 0, // No AAD
                        ciphertext, &encrypted_len,
                        ciphertext + encrypted_len - 16, 16) != CRYPTO_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    // Update the chain key
    if (derive_chain_key(session->sender_chain_key, PROTOCOL_SESSION_KEY_SIZE,
                         session->sender_chain_key, PROTOCOL_SESSION_KEY_SIZE,
                         "ChainKey") != PROTOCOL_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    session->sender_chain_key_id++;

    *ciphertext_len = encrypted_len;
    return PROTOCOL_OK;
}

protocol_error_t protocol_decrypt_message(protocol_session_state_t *session,
                                          const uint8_t *ciphertext, size_t ciphertext_len,
                                          uint8_t *message, size_t *message_len)
{
    if (!session || !ciphertext || !message || !message_len)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    if (ciphertext_len < 16)
    { // Minimum size for MAC
        return PROTOCOL_ERROR_INVALID_MESSAGE;
    }

    // Derive the message key
    uint8_t message_key[32];
    if (derive_message_key(message_key, sizeof(message_key),
                           session->receiver_chain_key, PROTOCOL_SESSION_KEY_SIZE) != PROTOCOL_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    // Decrypt the message
    size_t decrypted_len = ciphertext_len - 16; // Remove MAC
    if (*message_len < decrypted_len)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    if (aes_gcm_decrypt((aes_key_t *)message_key, NULL, 0, // No IV in this example
                        ciphertext, decrypted_len,
                        NULL, 0,                        // No AAD
                        ciphertext + decrypted_len, 16, // MAC
                        message, message_len) != CRYPTO_OK)
    {
        return PROTOCOL_ERROR_INVALID_MAC;
    }

    // Update the chain key
    if (derive_chain_key(session->receiver_chain_key, PROTOCOL_SESSION_KEY_SIZE,
                         session->receiver_chain_key, PROTOCOL_SESSION_KEY_SIZE,
                         "ChainKey") != PROTOCOL_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    session->receiver_chain_key_id++;

    return PROTOCOL_OK;
}

// Key generation
protocol_error_t protocol_generate_identity_key_pair(protocol_identity_key_t *identity_key)
{
    if (!identity_key)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    if (curve25519_generate_keypair(&identity_key->key, NULL) != CRYPTO_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    // Sign the public key with itself (simplified for this example)
    if (hmac_sha256((hmac_key_t *)identity_key->key.key,
                    identity_key->key.key, CURVE25519_KEY_SIZE,
                    identity_key->signature, NULL) != CRYPTO_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    return PROTOCOL_OK;
}

protocol_error_t protocol_generate_pre_key(protocol_pre_key_t *pre_key, uint32_t key_id)
{
    if (!pre_key)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    pre_key->key_id = key_id;
    if (curve25519_generate_keypair(&pre_key->key, NULL) != CRYPTO_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    return PROTOCOL_OK;
}

protocol_error_t protocol_generate_signed_pre_key(protocol_signed_pre_key_t *signed_pre_key,
                                                  const protocol_identity_key_t *identity_key,
                                                  uint32_t key_id)
{
    if (!signed_pre_key || !identity_key)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    signed_pre_key->key_id = key_id;
    if (curve25519_generate_keypair(&signed_pre_key->key, NULL) != CRYPTO_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    // Sign the pre key with the identity key
    if (hmac_sha256((hmac_key_t *)identity_key->key.key,
                    signed_pre_key->key.key, CURVE25519_KEY_SIZE,
                    signed_pre_key->signature, NULL) != CRYPTO_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    return PROTOCOL_OK;
}

// Key verification
protocol_error_t protocol_verify_identity_key(const protocol_identity_key_t *identity_key)
{
    if (!identity_key)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    // Verify the signature
    uint8_t computed_signature[64];
    if (hmac_sha256((hmac_key_t *)identity_key->key.key,
                    identity_key->key.key, CURVE25519_KEY_SIZE,
                    computed_signature, NULL) != CRYPTO_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    if (memcmp(computed_signature, identity_key->signature, 64) != 0)
    {
        return PROTOCOL_ERROR_INVALID_SIGNATURE;
    }

    return PROTOCOL_OK;
}

protocol_error_t protocol_verify_signed_pre_key(const protocol_signed_pre_key_t *signed_pre_key,
                                                const protocol_identity_key_t *identity_key)
{
    if (!signed_pre_key || !identity_key)
    {
        return PROTOCOL_ERROR_INVALID_PARAMETER;
    }

    // Verify the signature
    uint8_t computed_signature[64];
    if (hmac_sha256((hmac_key_t *)identity_key->key.key,
                    signed_pre_key->key.key, CURVE25519_KEY_SIZE,
                    computed_signature, NULL) != CRYPTO_OK)
    {
        return PROTOCOL_ERROR_INTERNAL;
    }

    if (memcmp(computed_signature, signed_pre_key->signature, 64) != 0)
    {
        return PROTOCOL_ERROR_INVALID_SIGNATURE;
    }

    return PROTOCOL_OK;
}