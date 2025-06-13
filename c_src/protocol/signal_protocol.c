#include "signal_protocol.h"
#include <stdlib.h>
#include <string.h>

// Helper functions for key derivation
static signal_error_t derive_chain_key(uint8_t* chain_key, size_t chain_key_len,
                                     const uint8_t* input_key, size_t input_key_len,
                                     const char* label) {
    if (!chain_key || !input_key || !label) {
        return SIGNAL_ERROR_INVALID_PARAMETER;
    }

    // Use HKDF to derive the chain key
    uint8_t info[32];
    size_t info_len = strlen(label);
    if (info_len > sizeof(info)) {
        return SIGNAL_ERROR_INVALID_PARAMETER;
    }
    memcpy(info, label, info_len);

    uint8_t salt[32] = {0};  // Zero salt for chain key derivation
    if (!HMAC(EVP_sha256(), salt, sizeof(salt),
              input_key, input_key_len,
              chain_key, (unsigned int*)&chain_key_len)) {
        return SIGNAL_ERROR_INTERNAL;
    }

    return SIGNAL_OK;
}

static signal_error_t derive_message_key(uint8_t* message_key, size_t message_key_len,
                                       const uint8_t* chain_key, size_t chain_key_len) {
    return derive_chain_key(message_key, message_key_len,
                          chain_key, chain_key_len,
                          "MessageKey");
}

// Protocol store management
signal_error_t signal_protocol_store_create(signal_protocol_store_t** store) {
    if (!store) {
        return SIGNAL_ERROR_INVALID_PARAMETER;
    }

    *store = calloc(1, sizeof(signal_protocol_store_t));
    if (!*store) {
        return SIGNAL_ERROR_MEMORY;
    }

    return SIGNAL_OK;
}

void signal_protocol_store_destroy(signal_protocol_store_t* store) {
    if (store) {
        if (store->pre_keys) {
            free(store->pre_keys);
        }
        if (store->signed_pre_keys) {
            free(store->signed_pre_keys);
        }
        free(store);
    }
}

// Session management
signal_error_t signal_session_create(signal_session_state_t** session,
                                   const signal_protocol_store_t* store,
                                   const signal_identity_key_t* local_identity_key,
                                   const signal_identity_key_t* remote_identity_key) {
    if (!session || !store || !local_identity_key || !remote_identity_key) {
        return SIGNAL_ERROR_INVALID_PARAMETER;
    }

    *session = calloc(1, sizeof(signal_session_state_t));
    if (!*session) {
        return SIGNAL_ERROR_MEMORY;
    }

    (*session)->session_version = SIGNAL_PROTOCOL_VERSION;
    (*session)->local_registration_id = store->registration_id;
    memcpy(&(*session)->local_identity_key, local_identity_key, sizeof(signal_identity_key_t));
    memcpy(&(*session)->remote_identity_key, remote_identity_key, sizeof(signal_identity_key_t));

    // Initialize chain keys with random values
    if (crypto_random_bytes((*session)->sender_chain_key, SIGNAL_SESSION_KEY_SIZE) != CRYPTO_OK ||
        crypto_random_bytes((*session)->receiver_chain_key, SIGNAL_SESSION_KEY_SIZE) != CRYPTO_OK ||
        crypto_random_bytes((*session)->root_key, SIGNAL_SESSION_KEY_SIZE) != CRYPTO_OK) {
        free(*session);
        return SIGNAL_ERROR_INTERNAL;
    }

    return SIGNAL_OK;
}

void signal_session_destroy(signal_session_state_t* session) {
    if (session) {
        crypto_secure_zero(session, sizeof(signal_session_state_t));
        free(session);
    }
}

// Message processing
signal_error_t signal_process_pre_key_bundle(signal_session_state_t* session,
                                           const signal_pre_key_bundle_t* bundle) {
    if (!session || !bundle) {
        return SIGNAL_ERROR_INVALID_PARAMETER;
    }

    if (bundle->version != SIGNAL_PROTOCOL_VERSION) {
        return SIGNAL_ERROR_INVALID_VERSION;
    }

    // Verify the identity key
    if (signal_verify_identity_key(&bundle->identity_key) != SIGNAL_OK) {
        return SIGNAL_ERROR_INVALID_KEY;
    }

    // Store the remote registration ID
    session->remote_registration_id = bundle->registration_id;

    // Perform the X3DH key agreement
    uint8_t shared_secret[32];
    size_t shared_secret_len;

    // 1. DH(identity_key, base_key)
    if (curve25519_shared_secret(&session->local_identity_key.key,
                                &bundle->base_key.key,
                                shared_secret, &shared_secret_len) != CRYPTO_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    // 2. DH(ephemeral_key, identity_key)
    uint8_t shared_secret2[32];
    size_t shared_secret2_len;
    if (curve25519_shared_secret(&session->local_identity_key.key,
                                &bundle->identity_key.key,
                                shared_secret2, &shared_secret2_len) != CRYPTO_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    // 3. DH(ephemeral_key, base_key)
    uint8_t shared_secret3[32];
    size_t shared_secret3_len;
    if (curve25519_shared_secret(&session->local_identity_key.key,
                                &bundle->base_key.key,
                                shared_secret3, &shared_secret3_len) != CRYPTO_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    // Combine the shared secrets
    uint8_t combined_secret[96];
    memcpy(combined_secret, shared_secret, 32);
    memcpy(combined_secret + 32, shared_secret2, 32);
    memcpy(combined_secret + 64, shared_secret3, 32);

    // Derive the root key and chain keys
    if (derive_chain_key(session->root_key, SIGNAL_SESSION_KEY_SIZE,
                        combined_secret, sizeof(combined_secret),
                        "RootKey") != SIGNAL_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    if (derive_chain_key(session->sender_chain_key, SIGNAL_SESSION_KEY_SIZE,
                        session->root_key, SIGNAL_SESSION_KEY_SIZE,
                        "SenderChainKey") != SIGNAL_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    if (derive_chain_key(session->receiver_chain_key, SIGNAL_SESSION_KEY_SIZE,
                        session->root_key, SIGNAL_SESSION_KEY_SIZE,
                        "ReceiverChainKey") != SIGNAL_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    return SIGNAL_OK;
}

signal_error_t signal_encrypt_message(signal_session_state_t* session,
                                    const uint8_t* message, size_t message_len,
                                    uint8_t* ciphertext, size_t* ciphertext_len) {
    if (!session || !message || !ciphertext || !ciphertext_len) {
        return SIGNAL_ERROR_INVALID_PARAMETER;
    }

    // Generate a new ephemeral key pair
    curve25519_key_t ephemeral_key;
    if (curve25519_generate_keypair(&ephemeral_key, NULL) != CRYPTO_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    // Derive the message key
    uint8_t message_key[32];
    if (derive_message_key(message_key, sizeof(message_key),
                          session->sender_chain_key, SIGNAL_SESSION_KEY_SIZE) != SIGNAL_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    // Encrypt the message
    uint8_t iv[12];
    if (crypto_random_bytes(iv, sizeof(iv)) != CRYPTO_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    size_t encrypted_len = message_len + 16;  // Message + MAC
    if (*ciphertext_len < encrypted_len) {
        return SIGNAL_ERROR_INVALID_PARAMETER;
    }

    if (aes_gcm_encrypt((aes_key_t*)message_key, iv, sizeof(iv),
                        message, message_len,
                        NULL, 0,  // No AAD
                        ciphertext, &encrypted_len,
                        ciphertext + encrypted_len - 16, 16) != CRYPTO_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    // Update the chain key
    if (derive_chain_key(session->sender_chain_key, SIGNAL_SESSION_KEY_SIZE,
                        session->sender_chain_key, SIGNAL_SESSION_KEY_SIZE,
                        "ChainKey") != SIGNAL_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    session->sender_chain_key_id++;

    *ciphertext_len = encrypted_len;
    return SIGNAL_OK;
}

signal_error_t signal_decrypt_message(signal_session_state_t* session,
                                    const uint8_t* ciphertext, size_t ciphertext_len,
                                    uint8_t* message, size_t* message_len) {
    if (!session || !ciphertext || !message || !message_len) {
        return SIGNAL_ERROR_INVALID_PARAMETER;
    }

    if (ciphertext_len < 16) {  // Minimum size for MAC
        return SIGNAL_ERROR_INVALID_MESSAGE;
    }

    // Derive the message key
    uint8_t message_key[32];
    if (derive_message_key(message_key, sizeof(message_key),
                          session->receiver_chain_key, SIGNAL_SESSION_KEY_SIZE) != SIGNAL_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    // Decrypt the message
    size_t decrypted_len = ciphertext_len - 16;  // Remove MAC
    if (*message_len < decrypted_len) {
        return SIGNAL_ERROR_INVALID_PARAMETER;
    }

    if (aes_gcm_decrypt((aes_key_t*)message_key, NULL, 0,  // No IV in this example
                        ciphertext, decrypted_len,
                        NULL, 0,  // No AAD
                        ciphertext + decrypted_len, 16,  // MAC
                        message, message_len) != CRYPTO_OK) {
        return SIGNAL_ERROR_INVALID_MAC;
    }

    // Update the chain key
    if (derive_chain_key(session->receiver_chain_key, SIGNAL_SESSION_KEY_SIZE,
                        session->receiver_chain_key, SIGNAL_SESSION_KEY_SIZE,
                        "ChainKey") != SIGNAL_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    session->receiver_chain_key_id++;

    return SIGNAL_OK;
}

// Key generation
signal_error_t signal_generate_identity_key_pair(signal_identity_key_t* identity_key) {
    if (!identity_key) {
        return SIGNAL_ERROR_INVALID_PARAMETER;
    }

    if (curve25519_generate_keypair(&identity_key->key, NULL) != CRYPTO_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    // Sign the public key with itself (simplified for this example)
    if (hmac_sha256((hmac_key_t*)identity_key->key.key,
                    identity_key->key.key, CURVE25519_KEY_SIZE,
                    identity_key->signature, NULL) != CRYPTO_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    return SIGNAL_OK;
}

signal_error_t signal_generate_pre_key(signal_pre_key_t* pre_key, uint32_t key_id) {
    if (!pre_key) {
        return SIGNAL_ERROR_INVALID_PARAMETER;
    }

    pre_key->key_id = key_id;
    if (curve25519_generate_keypair(&pre_key->key, NULL) != CRYPTO_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    return SIGNAL_OK;
}

signal_error_t signal_generate_signed_pre_key(signal_signed_pre_key_t* signed_pre_key,
                                            const signal_identity_key_t* identity_key,
                                            uint32_t key_id) {
    if (!signed_pre_key || !identity_key) {
        return SIGNAL_ERROR_INVALID_PARAMETER;
    }

    signed_pre_key->key_id = key_id;
    if (curve25519_generate_keypair(&signed_pre_key->key, NULL) != CRYPTO_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    // Sign the pre key with the identity key
    if (hmac_sha256((hmac_key_t*)identity_key->key.key,
                    signed_pre_key->key.key, CURVE25519_KEY_SIZE,
                    signed_pre_key->signature, NULL) != CRYPTO_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    return SIGNAL_OK;
}

// Key verification
signal_error_t signal_verify_identity_key(const signal_identity_key_t* identity_key) {
    if (!identity_key) {
        return SIGNAL_ERROR_INVALID_PARAMETER;
    }

    // Verify the signature
    uint8_t computed_signature[64];
    if (hmac_sha256((hmac_key_t*)identity_key->key.key,
                    identity_key->key.key, CURVE25519_KEY_SIZE,
                    computed_signature, NULL) != CRYPTO_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    if (memcmp(computed_signature, identity_key->signature, 64) != 0) {
        return SIGNAL_ERROR_INVALID_SIGNATURE;
    }

    return SIGNAL_OK;
}

signal_error_t signal_verify_signed_pre_key(const signal_signed_pre_key_t* signed_pre_key,
                                          const signal_identity_key_t* identity_key) {
    if (!signed_pre_key || !identity_key) {
        return SIGNAL_ERROR_INVALID_PARAMETER;
    }

    // Verify the signature
    uint8_t computed_signature[64];
    if (hmac_sha256((hmac_key_t*)identity_key->key.key,
                    signed_pre_key->key.key, CURVE25519_KEY_SIZE,
                    computed_signature, NULL) != CRYPTO_OK) {
        return SIGNAL_ERROR_INTERNAL;
    }

    if (memcmp(computed_signature, signed_pre_key->signature, 64) != 0) {
        return SIGNAL_ERROR_INVALID_SIGNATURE;
    }

    return SIGNAL_OK;
} 