#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>
#include "../crypto/crypto.h"

// Protocol version
#define PROTOCOL_VERSION 1

// Key sizes
#define PROTOCOL_IDENTITY_KEY_SIZE CURVE25519_KEY_SIZE
#define PROTOCOL_PRE_KEY_SIZE CURVE25519_KEY_SIZE
#define PROTOCOL_SIGNED_PRE_KEY_SIZE CURVE25519_KEY_SIZE
#define PROTOCOL_SESSION_KEY_SIZE 32
#define PROTOCOL_MESSAGE_OVERHEAD 53 // Header + MAC

// Ratchet constants
#define MESSAGE_KEY_LEN 32
#define CHAIN_KEY_LEN 32
#define ROOT_KEY_LEN 32
#define MAX_MESSAGE_KEYS 2000
#define MAX_SKIP_KEYS 100
#define RATCHET_ROTATION_THRESHOLD 100
#define MAX_SKIP 1000
#define MAX_SKIP_DISTANCE 1000
#define MESSAGE_KEY_CLEANUP_THRESHOLD 1000
#define SKIP_KEY_CLEANUP_THRESHOLD 50
#define MAX_KEY_AGE 10000

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

// Message key structure
typedef struct
{
    unsigned char key[MESSAGE_KEY_LEN];
    uint32_t index;
    uint32_t ratchet_index;
} protocol_message_key_t;

// Ratchet chain structure
typedef struct
{
    EVP_PKEY *dh_key;
    unsigned char chain_key[CHAIN_KEY_LEN];
    uint32_t chain_index;
    protocol_message_key_t message_keys[MAX_MESSAGE_KEYS];
    size_t message_key_count;
    protocol_message_key_t skip_keys[MAX_SKIP_KEYS];
    size_t skip_key_count;
} protocol_ratchet_chain_t;

// Advanced ratchet state structure
typedef struct
{
    protocol_ratchet_chain_t sending_chain;
    protocol_ratchet_chain_t receiving_chain;
    unsigned char root_key[ROOT_KEY_LEN];
    uint32_t sending_ratchet_index;
    uint32_t receiving_ratchet_index;
} protocol_ratchet_state_t;

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

// Advanced ratchet functions
protocol_error_t protocol_ratchet_state_create(protocol_ratchet_state_t **state);
void protocol_ratchet_state_destroy(protocol_ratchet_state_t *state);

// Key derivation functions
protocol_error_t protocol_derive_root_key(const unsigned char *dh_output, size_t dh_output_len,
                                          const unsigned char *salt, size_t salt_len,
                                          unsigned char *root_key);

protocol_error_t protocol_derive_chain_key(const unsigned char *root_key, size_t root_key_len,
                                           const unsigned char *salt, size_t salt_len,
                                           unsigned char *chain_key);

protocol_error_t protocol_derive_message_key(const unsigned char *chain_key, size_t chain_key_len,
                                             const unsigned char *salt, size_t salt_len,
                                             unsigned char *message_key);

// Ratchet chain management
protocol_error_t protocol_rotate_chain_key(protocol_ratchet_chain_t *chain);
protocol_error_t protocol_add_message_key(protocol_ratchet_chain_t *chain, const unsigned char *message_key);
protocol_error_t protocol_rotate_sending_ratchet(protocol_ratchet_state_t *state);
protocol_error_t protocol_rotate_receiving_ratchet(protocol_ratchet_state_t *state, EVP_PKEY *their_dh_key);

// Message key management
void protocol_cleanup_message_keys(protocol_ratchet_chain_t *chain);
void protocol_cleanup_skip_keys(protocol_ratchet_chain_t *chain);
void protocol_cleanup_ratchet_state(protocol_ratchet_state_t *state);

// DH shared secret calculation
protocol_error_t protocol_calculate_dh_shared_secret(EVP_PKEY *our_key, EVP_PKEY *their_key,
                                                     unsigned char *shared_secret, size_t *shared_secret_len);

// Bundle parsing helper functions
protocol_error_t protocol_parse_uint32(const unsigned char *data, uint32_t *value);
protocol_error_t protocol_parse_binary(const unsigned char *data, size_t data_len, size_t *offset,
                                       unsigned char **binary, size_t *binary_len);

#endif // PROTOCOL_H