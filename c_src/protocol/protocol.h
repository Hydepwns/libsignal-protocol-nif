#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include "../crypto/crypto.h"

// Protocol version
#define PROTOCOL_VERSION 1

// Key sizes
#define PROTOCOL_IDENTITY_KEY_SIZE CURVE25519_KEY_SIZE
#define PROTOCOL_PRE_KEY_SIZE CURVE25519_KEY_SIZE
#define PROTOCOL_SIGNED_PRE_KEY_SIZE CURVE25519_KEY_SIZE
#define PROTOCOL_SESSION_KEY_SIZE 32
#define PROTOCOL_MESSAGE_OVERHEAD 53 // Header + MAC

// Error codes
typedef enum
{
    PROTOCOL_OK = 0,
    PROTOCOL_ERROR_INVALID_PARAMETER = -1,
    PROTOCOL_ERROR_MEMORY = -2,
    PROTOCOL_ERROR_INTERNAL = -3,
    PROTOCOL_ERROR_INVALID_KEY = -4,
    PROTOCOL_ERROR_INVALID_MESSAGE = -5,
    PROTOCOL_ERROR_DUPLICATE_MESSAGE = -6,
    PROTOCOL_ERROR_INVALID_VERSION = -7,
    PROTOCOL_ERROR_LEGACY_MESSAGE = -8,
    PROTOCOL_ERROR_INVALID_MAC = -9,
    PROTOCOL_ERROR_INVALID_SIGNATURE = -10,
    PROTOCOL_ERROR_INVALID_PRE_KEY = -11,
    PROTOCOL_ERROR_INVALID_SESSION = -12
} protocol_error_t;

// Key types
typedef struct
{
    curve25519_key_t key;
    uint8_t signature[64]; // Ed25519 signature
} protocol_identity_key_t;

typedef struct
{
    uint32_t key_id;
    curve25519_key_t key;
} protocol_pre_key_t;

typedef struct
{
    uint32_t key_id;
    curve25519_key_t key;
    uint8_t signature[64]; // Ed25519 signature
} protocol_signed_pre_key_t;

typedef struct
{
    uint32_t registration_id;
    protocol_identity_key_t identity_key;
    protocol_pre_key_t *pre_keys;
    size_t pre_key_count;
    protocol_signed_pre_key_t *signed_pre_keys;
    size_t signed_pre_key_count;
} protocol_protocol_store_t;

// Session state
typedef struct
{
    uint32_t session_version;
    uint32_t local_registration_id;
    uint32_t remote_registration_id;
    protocol_identity_key_t local_identity_key;
    protocol_identity_key_t remote_identity_key;
    uint32_t sender_chain_key_id;
    uint8_t sender_chain_key[PROTOCOL_SESSION_KEY_SIZE];
    uint32_t receiver_chain_key_id;
    uint8_t receiver_chain_key[PROTOCOL_SESSION_KEY_SIZE];
    uint32_t root_key_id;
    uint8_t root_key[PROTOCOL_SESSION_KEY_SIZE];
} protocol_session_state_t;

// Message types
typedef struct
{
    uint8_t version;
    uint32_t registration_id;
    uint32_t pre_key_id;
    uint32_t signed_pre_key_id;
    protocol_identity_key_t base_key;
    protocol_identity_key_t identity_key;
    uint8_t message[0]; // Flexible array member
} protocol_pre_key_bundle_t;

typedef struct
{
    uint8_t version;
    uint32_t registration_id;
    uint32_t pre_key_id;
    uint32_t signed_pre_key_id;
    uint32_t base_key_id;
    protocol_identity_key_t base_key;
    protocol_identity_key_t identity_key;
    uint8_t message[0]; // Flexible array member
} protocol_pre_key_whisper_message_t;

typedef struct
{
    uint8_t version;
    uint32_t registration_id;
    uint32_t counter;
    uint32_t previous_counter;
    uint8_t ratchet_key[0]; // Flexible array member
    uint8_t ciphertext[0];  // Flexible array member
} protocol_whisper_message_t;

// Function declarations

// Protocol store management
protocol_error_t protocol_protocol_store_create(protocol_protocol_store_t **store);
void protocol_protocol_store_destroy(protocol_protocol_store_t *store);

// Session management
protocol_error_t protocol_session_create(protocol_session_state_t **session,
                                         const protocol_protocol_store_t *store,
                                         const protocol_identity_key_t *local_identity_key,
                                         const protocol_identity_key_t *remote_identity_key);
void protocol_session_destroy(protocol_session_state_t *session);

// Message processing
protocol_error_t protocol_process_pre_key_bundle(protocol_session_state_t *session,
                                                 const protocol_pre_key_bundle_t *bundle);

protocol_error_t protocol_encrypt_message(protocol_session_state_t *session,
                                          const uint8_t *message, size_t message_len,
                                          uint8_t *ciphertext, size_t *ciphertext_len);

protocol_error_t protocol_decrypt_message(protocol_session_state_t *session,
                                          const uint8_t *ciphertext, size_t ciphertext_len,
                                          uint8_t *message, size_t *message_len);

// Key generation
protocol_error_t protocol_generate_identity_key_pair(protocol_identity_key_t *identity_key);
protocol_error_t protocol_generate_pre_key(protocol_pre_key_t *pre_key, uint32_t key_id);
protocol_error_t protocol_generate_signed_pre_key(protocol_signed_pre_key_t *signed_pre_key,
                                                  const protocol_identity_key_t *identity_key,
                                                  uint32_t key_id);

// Key verification
protocol_error_t protocol_verify_identity_key(const protocol_identity_key_t *identity_key);
protocol_error_t protocol_verify_signed_pre_key(const protocol_signed_pre_key_t *signed_pre_key,
                                                const protocol_identity_key_t *identity_key);

#endif // PROTOCOL_H