#ifndef SIGNAL_PROTOCOL_H
#define SIGNAL_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include "../crypto/crypto.h"

// Protocol version
#define SIGNAL_PROTOCOL_VERSION 1

// Key sizes
#define SIGNAL_IDENTITY_KEY_SIZE CURVE25519_KEY_SIZE
#define SIGNAL_PRE_KEY_SIZE CURVE25519_KEY_SIZE
#define SIGNAL_SIGNED_PRE_KEY_SIZE CURVE25519_KEY_SIZE
#define SIGNAL_SESSION_KEY_SIZE 32
#define SIGNAL_MESSAGE_OVERHEAD 53  // Header + MAC

// Error codes
typedef enum {
    SIGNAL_OK = 0,
    SIGNAL_ERROR_INVALID_PARAMETER = -1,
    SIGNAL_ERROR_MEMORY = -2,
    SIGNAL_ERROR_INTERNAL = -3,
    SIGNAL_ERROR_INVALID_KEY = -4,
    SIGNAL_ERROR_INVALID_MESSAGE = -5,
    SIGNAL_ERROR_DUPLICATE_MESSAGE = -6,
    SIGNAL_ERROR_INVALID_VERSION = -7,
    SIGNAL_ERROR_LEGACY_MESSAGE = -8,
    SIGNAL_ERROR_INVALID_MAC = -9,
    SIGNAL_ERROR_INVALID_SIGNATURE = -10,
    SIGNAL_ERROR_INVALID_PRE_KEY = -11,
    SIGNAL_ERROR_INVALID_SESSION = -12
} signal_error_t;

// Key types
typedef struct {
    curve25519_key_t key;
    uint8_t signature[64];  // Ed25519 signature
} signal_identity_key_t;

typedef struct {
    uint32_t key_id;
    curve25519_key_t key;
} signal_pre_key_t;

typedef struct {
    uint32_t key_id;
    curve25519_key_t key;
    uint8_t signature[64];  // Ed25519 signature
} signal_signed_pre_key_t;

typedef struct {
    uint32_t registration_id;
    signal_identity_key_t identity_key;
    signal_pre_key_t* pre_keys;
    size_t pre_key_count;
    signal_signed_pre_key_t* signed_pre_keys;
    size_t signed_pre_key_count;
} signal_protocol_store_t;

// Session state
typedef struct {
    uint32_t session_version;
    uint32_t local_registration_id;
    uint32_t remote_registration_id;
    signal_identity_key_t local_identity_key;
    signal_identity_key_t remote_identity_key;
    uint32_t sender_chain_key_id;
    uint8_t sender_chain_key[SIGNAL_SESSION_KEY_SIZE];
    uint32_t receiver_chain_key_id;
    uint8_t receiver_chain_key[SIGNAL_SESSION_KEY_SIZE];
    uint32_t root_key_id;
    uint8_t root_key[SIGNAL_SESSION_KEY_SIZE];
} signal_session_state_t;

// Message types
typedef struct {
    uint8_t version;
    uint32_t registration_id;
    uint32_t pre_key_id;
    uint32_t signed_pre_key_id;
    signal_identity_key_t base_key;
    signal_identity_key_t identity_key;
    uint8_t message[0];  // Flexible array member
} signal_pre_key_bundle_t;

typedef struct {
    uint8_t version;
    uint32_t registration_id;
    uint32_t pre_key_id;
    uint32_t signed_pre_key_id;
    uint32_t base_key_id;
    signal_identity_key_t base_key;
    signal_identity_key_t identity_key;
    uint8_t message[0];  // Flexible array member
} signal_pre_key_whisper_message_t;

typedef struct {
    uint8_t version;
    uint32_t registration_id;
    uint32_t counter;
    uint32_t previous_counter;
    uint8_t ratchet_key[0];  // Flexible array member
    uint8_t ciphertext[0];   // Flexible array member
} signal_whisper_message_t;

// Function declarations

// Protocol store management
signal_error_t signal_protocol_store_create(signal_protocol_store_t** store);
void signal_protocol_store_destroy(signal_protocol_store_t* store);

// Session management
signal_error_t signal_session_create(signal_session_state_t** session,
                                   const signal_protocol_store_t* store,
                                   const signal_identity_key_t* local_identity_key,
                                   const signal_identity_key_t* remote_identity_key);
void signal_session_destroy(signal_session_state_t* session);

// Message processing
signal_error_t signal_process_pre_key_bundle(signal_session_state_t* session,
                                           const signal_pre_key_bundle_t* bundle);

signal_error_t signal_encrypt_message(signal_session_state_t* session,
                                    const uint8_t* message, size_t message_len,
                                    uint8_t* ciphertext, size_t* ciphertext_len);

signal_error_t signal_decrypt_message(signal_session_state_t* session,
                                    const uint8_t* ciphertext, size_t ciphertext_len,
                                    uint8_t* message, size_t* message_len);

// Key generation
signal_error_t signal_generate_identity_key_pair(signal_identity_key_t* identity_key);
signal_error_t signal_generate_pre_key(signal_pre_key_t* pre_key, uint32_t key_id);
signal_error_t signal_generate_signed_pre_key(signal_signed_pre_key_t* signed_pre_key,
                                            const signal_identity_key_t* identity_key,
                                            uint32_t key_id);

// Key verification
signal_error_t signal_verify_identity_key(const signal_identity_key_t* identity_key);
signal_error_t signal_verify_signed_pre_key(const signal_signed_pre_key_t* signed_pre_key,
                                          const signal_identity_key_t* identity_key);

#endif // SIGNAL_PROTOCOL_H 