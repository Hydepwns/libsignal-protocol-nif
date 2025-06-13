#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/curve25519.h>
#include <string.h>

// AES-256-GCM implementation
crypto_error_t aes_gcm_encrypt(const aes_key_t* key,
                              const uint8_t* iv, size_t iv_len,
                              const uint8_t* plaintext, size_t plaintext_len,
                              const uint8_t* aad, size_t aad_len,
                              uint8_t* ciphertext, size_t* ciphertext_len,
                              uint8_t* tag, size_t tag_len) {
    if (!key || !iv || !plaintext || !ciphertext || !tag) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return CRYPTO_ERROR_MEMORY;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key->key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_INTERNAL;
    }

    if (aad && aad_len > 0) {
        int len;
        if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
            EVP_CIPHER_CTX_free(ctx);
            return CRYPTO_ERROR_INTERNAL;
        }
    }

    int len;
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_INTERNAL;
    }
    *ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_INTERNAL;
    }
    *ciphertext_len += len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_INTERNAL;
    }

    EVP_CIPHER_CTX_free(ctx);
    return CRYPTO_OK;
}

crypto_error_t aes_gcm_decrypt(const aes_key_t* key,
                              const uint8_t* iv, size_t iv_len,
                              const uint8_t* ciphertext, size_t ciphertext_len,
                              const uint8_t* aad, size_t aad_len,
                              const uint8_t* tag, size_t tag_len,
                              uint8_t* plaintext, size_t* plaintext_len) {
    if (!key || !iv || !ciphertext || !tag || !plaintext) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return CRYPTO_ERROR_MEMORY;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key->key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_INTERNAL;
    }

    if (aad && aad_len > 0) {
        int len;
        if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
            EVP_CIPHER_CTX_free(ctx);
            return CRYPTO_ERROR_INTERNAL;
        }
    }

    int len;
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_INTERNAL;
    }
    *plaintext_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, (void*)tag)) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_INVALID_SIGNATURE;
    }

    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_INVALID_SIGNATURE;
    }
    *plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return CRYPTO_OK;
}

// HMAC-SHA256 implementation
crypto_error_t hmac_sha256(const hmac_key_t* key,
                          const uint8_t* data, size_t data_len,
                          uint8_t* mac, size_t* mac_len) {
    if (!key || !data || !mac) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    unsigned int len;
    if (!HMAC(EVP_sha256(), key->key, HMAC_KEY_SIZE,
              data, data_len, mac, &len)) {
        return CRYPTO_ERROR_INTERNAL;
    }

    *mac_len = len;
    return CRYPTO_OK;
}

// Curve25519 implementation
crypto_error_t curve25519_generate_keypair(curve25519_key_t* public_key,
                                         curve25519_key_t* private_key) {
    if (!public_key || !private_key) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    if (!ED25519_keypair(public_key->key, private_key->key)) {
        return CRYPTO_ERROR_INTERNAL;
    }

    return CRYPTO_OK;
}

crypto_error_t curve25519_shared_secret(const curve25519_key_t* private_key,
                                      const curve25519_key_t* public_key,
                                      uint8_t* shared_secret,
                                      size_t* shared_secret_len) {
    if (!private_key || !public_key || !shared_secret) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    if (!ED25519_shared_secret(shared_secret, private_key->key, public_key->key)) {
        return CRYPTO_ERROR_INTERNAL;
    }

    *shared_secret_len = CURVE25519_KEY_SIZE;
    return CRYPTO_OK;
}

// SHA-256 implementation
crypto_error_t sha256(const uint8_t* data, size_t data_len,
                     uint8_t* digest, size_t* digest_len) {
    if (!data || !digest) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    if (!SHA256(data, data_len, digest)) {
        return CRYPTO_ERROR_INTERNAL;
    }

    *digest_len = SHA256_DIGEST_SIZE;
    return CRYPTO_OK;
}

// SHA-512 implementation
crypto_error_t sha512(const uint8_t* data, size_t data_len,
                     uint8_t* digest, size_t* digest_len) {
    if (!data || !digest) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    if (!SHA512(data, data_len, digest)) {
        return CRYPTO_ERROR_INTERNAL;
    }

    *digest_len = SHA512_DIGEST_SIZE;
    return CRYPTO_OK;
}

// Random number generation
crypto_error_t crypto_random_bytes(uint8_t* buffer, size_t len) {
    if (!buffer) {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    if (!RAND_bytes(buffer, len)) {
        return CRYPTO_ERROR_INTERNAL;
    }

    return CRYPTO_OK;
}

// Memory security
void crypto_secure_zero(void* buffer, size_t len) {
    if (buffer) {
        volatile uint8_t* p = buffer;
        while (len--) {
            *p++ = 0;
        }
    }
} 