#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// Key sizes
#define AES_KEY_SIZE 32
#define HMAC_KEY_SIZE 32
#define CURVE25519_KEY_SIZE 32
#define SHA256_DIGEST_SIZE 32
#define SHA512_DIGEST_SIZE 64
#define EC_PUBLIC_KEY_SIZE 65  // Uncompressed P-256 point
#define EC_PRIVATE_KEY_SIZE 32 // P-256 private key
#define EC_SIGNATURE_SIZE 64   // ECDSA signature (r + s)

// Error codes
typedef enum
{
    CRYPTO_OK = 0,
    CRYPTO_ERROR_INVALID_PARAMETER = -1,
    CRYPTO_ERROR_MEMORY = -2,
    CRYPTO_ERROR_INTERNAL = -3,
    CRYPTO_ERROR_INVALID_KEY = -4,
    CRYPTO_ERROR_INVALID_SIGNATURE = -5
} crypto_error_t;

// Key types
typedef struct
{
    uint8_t key[AES_KEY_SIZE];
} aes_key_t;

typedef struct
{
    uint8_t key[HMAC_KEY_SIZE];
} hmac_key_t;

typedef struct
{
    uint8_t key[CURVE25519_KEY_SIZE];
} curve25519_key_t;

// Function declarations

// AES-256-GCM
crypto_error_t aes_gcm_encrypt(const aes_key_t *key,
                               const uint8_t *iv, size_t iv_len,
                               const uint8_t *plaintext, size_t plaintext_len,
                               const uint8_t *aad, size_t aad_len,
                               uint8_t *ciphertext, size_t *ciphertext_len,
                               uint8_t *tag, size_t tag_len);

crypto_error_t aes_gcm_decrypt(const aes_key_t *key,
                               const uint8_t *iv, size_t iv_len,
                               const uint8_t *ciphertext, size_t ciphertext_len,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *tag, size_t tag_len,
                               uint8_t *plaintext, size_t *plaintext_len);

// HMAC-SHA256
crypto_error_t hmac_sha256(const hmac_key_t *key,
                           const uint8_t *data, size_t data_len,
                           uint8_t *mac, size_t *mac_len);

// Curve25519
crypto_error_t curve25519_generate_keypair(curve25519_key_t *public_key,
                                           curve25519_key_t *private_key);

crypto_error_t curve25519_shared_secret(const curve25519_key_t *private_key,
                                        const curve25519_key_t *public_key,
                                        uint8_t *shared_secret,
                                        size_t *shared_secret_len);

// SHA-256
crypto_error_t sha256(const uint8_t *data, size_t data_len,
                      uint8_t *digest, size_t *digest_len);

// SHA-512
crypto_error_t sha512(const uint8_t *data, size_t data_len,
                      uint8_t *digest, size_t *digest_len);

// Random number generation
crypto_error_t crypto_random_bytes(uint8_t *buffer, size_t len);

// Memory security
void crypto_secure_zero(void *buffer, size_t len);

// New EVP_PKEY-based functions (replacing deprecated EC_KEY API)
crypto_error_t evp_generate_ec_keypair(EVP_PKEY **public_key, EVP_PKEY **private_key);
crypto_error_t evp_sign_data(EVP_PKEY *private_key, const uint8_t *data, size_t data_len,
                             uint8_t *signature, size_t *signature_len);
crypto_error_t evp_verify_signature(EVP_PKEY *public_key, const uint8_t *data, size_t data_len,
                                    const uint8_t *signature, size_t signature_len);
crypto_error_t evp_serialize_public_key(EVP_PKEY *key, uint8_t *buffer, size_t *buffer_len);
crypto_error_t evp_deserialize_public_key(const uint8_t *buffer, size_t buffer_len, EVP_PKEY **key);
crypto_error_t evp_serialize_private_key(EVP_PKEY *key, uint8_t *buffer, size_t *buffer_len);
crypto_error_t evp_deserialize_private_key(const uint8_t *buffer, size_t buffer_len, EVP_PKEY **key);
crypto_error_t evp_validate_key(EVP_PKEY *key);

#endif // CRYPTO_H