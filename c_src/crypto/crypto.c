#include "crypto.h"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <string.h>

// AES-256-GCM implementation
crypto_error_t aes_gcm_encrypt(const aes_key_t *key,
                               const uint8_t *iv, size_t iv_len,
                               const uint8_t *plaintext, size_t plaintext_len,
                               const uint8_t *aad, size_t aad_len,
                               uint8_t *ciphertext, size_t *ciphertext_len,
                               uint8_t *tag, size_t tag_len)
{
    if (!key || !iv || !plaintext || !ciphertext || !tag)
    {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return CRYPTO_ERROR_MEMORY;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key->key, iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_INTERNAL;
    }

    if (aad && aad_len > 0)
    {
        int len;
        if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        {
            EVP_CIPHER_CTX_free(ctx);
            return CRYPTO_ERROR_INTERNAL;
        }
    }

    int len;
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_INTERNAL;
    }
    *ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_INTERNAL;
    }
    *ciphertext_len += len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_INTERNAL;
    }

    EVP_CIPHER_CTX_free(ctx);
    return CRYPTO_OK;
}

crypto_error_t aes_gcm_decrypt(const aes_key_t *key,
                               const uint8_t *iv, size_t iv_len,
                               const uint8_t *ciphertext, size_t ciphertext_len,
                               const uint8_t *aad, size_t aad_len,
                               const uint8_t *tag, size_t tag_len,
                               uint8_t *plaintext, size_t *plaintext_len)
{
    if (!key || !iv || !ciphertext || !tag || !plaintext)
    {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return CRYPTO_ERROR_MEMORY;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key->key, iv))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_INTERNAL;
    }

    if (aad && aad_len > 0)
    {
        int len;
        if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        {
            EVP_CIPHER_CTX_free(ctx);
            return CRYPTO_ERROR_INTERNAL;
        }
    }

    int len;
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_INTERNAL;
    }
    *plaintext_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, (void *)tag))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_INVALID_SIGNATURE;
    }

    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_ERROR_INVALID_SIGNATURE;
    }
    *plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return CRYPTO_OK;
}

// HMAC-SHA256 implementation
crypto_error_t hmac_sha256(const hmac_key_t *key,
                           const uint8_t *data, size_t data_len,
                           uint8_t *mac, size_t *mac_len)
{
    if (!key || !data || !mac)
    {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    unsigned int len;
    if (!HMAC(EVP_sha256(), key->key, HMAC_KEY_SIZE,
              data, data_len, mac, &len))
    {
        return CRYPTO_ERROR_INTERNAL;
    }

    *mac_len = len;
    return CRYPTO_OK;
}

// Curve25519 implementation (X25519 via OpenSSL EVP_PKEY API)
crypto_error_t curve25519_generate_keypair(curve25519_key_t *public_key,
                                           curve25519_key_t *private_key)
{
    if (!public_key || !private_key)
    {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!pctx)
        return CRYPTO_ERROR_INTERNAL;
    if (EVP_PKEY_keygen_init(pctx) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        return CRYPTO_ERROR_INTERNAL;
    }
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        return CRYPTO_ERROR_INTERNAL;
    }
    // Extract private key
    size_t priv_len = CURVE25519_KEY_SIZE;
    if (EVP_PKEY_get_raw_private_key(pkey, private_key->key, &priv_len) <= 0 || priv_len != CURVE25519_KEY_SIZE)
    {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return CRYPTO_ERROR_INTERNAL;
    }
    // Extract public key
    size_t pub_len = CURVE25519_KEY_SIZE;
    if (EVP_PKEY_get_raw_public_key(pkey, public_key->key, &pub_len) <= 0 || pub_len != CURVE25519_KEY_SIZE)
    {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(pctx);
        return CRYPTO_ERROR_INTERNAL;
    }
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    return CRYPTO_OK;
}

crypto_error_t curve25519_shared_secret(const curve25519_key_t *private_key,
                                        const curve25519_key_t *public_key,
                                        uint8_t *shared_secret,
                                        size_t *shared_secret_len)
{
    if (!private_key || !public_key || !shared_secret || !shared_secret_len)
    {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }
    EVP_PKEY *priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_key->key, CURVE25519_KEY_SIZE);
    EVP_PKEY *pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, public_key->key, CURVE25519_KEY_SIZE);
    if (!priv || !pub)
    {
        if (priv)
            EVP_PKEY_free(priv);
        if (pub)
            EVP_PKEY_free(pub);
        return CRYPTO_ERROR_INTERNAL;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx)
    {
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        return CRYPTO_ERROR_INTERNAL;
    }
    if (EVP_PKEY_derive_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        return CRYPTO_ERROR_INTERNAL;
    }
    if (EVP_PKEY_derive_set_peer(ctx, pub) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        return CRYPTO_ERROR_INTERNAL;
    }
    size_t secret_len = CURVE25519_KEY_SIZE;
    if (EVP_PKEY_derive(ctx, shared_secret, &secret_len) <= 0 || secret_len != CURVE25519_KEY_SIZE)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        return CRYPTO_ERROR_INTERNAL;
    }
    *shared_secret_len = secret_len;
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    return CRYPTO_OK;
}

// SHA-256 implementation
crypto_error_t sha256(const uint8_t *data, size_t data_len,
                      uint8_t *digest, size_t *digest_len)
{
    if (!data || !digest)
    {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    if (!SHA256(data, data_len, digest))
    {
        return CRYPTO_ERROR_INTERNAL;
    }

    *digest_len = SHA256_DIGEST_SIZE;
    return CRYPTO_OK;
}

// SHA-512 implementation
crypto_error_t sha512(const uint8_t *data, size_t data_len,
                      uint8_t *digest, size_t *digest_len)
{
    if (!data || !digest)
    {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    if (!SHA512(data, data_len, digest))
    {
        return CRYPTO_ERROR_INTERNAL;
    }

    *digest_len = SHA512_DIGEST_SIZE;
    return CRYPTO_OK;
}

// Random number generation
crypto_error_t crypto_random_bytes(uint8_t *buffer, size_t len)
{
    if (!buffer)
    {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    if (!RAND_bytes(buffer, len))
    {
        return CRYPTO_ERROR_INTERNAL;
    }

    return CRYPTO_OK;
}

// Memory security
void crypto_secure_zero(void *buffer, size_t len)
{
    if (buffer)
    {
        volatile uint8_t *p = buffer;
        while (len--)
        {
            *p++ = 0;
        }
    }
}

// New EVP_PKEY-based functions (replacing deprecated EC_KEY API)

crypto_error_t evp_generate_ec_keypair(EVP_PKEY **public_key, EVP_PKEY **private_key)
{
    if (!public_key || !private_key)
    {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx)
    {
        return CRYPTO_ERROR_INTERNAL;
    }

    if (EVP_PKEY_keygen_init(pctx) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        return CRYPTO_ERROR_INTERNAL;
    }

    // Set curve to P-256
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        return CRYPTO_ERROR_INTERNAL;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        return CRYPTO_ERROR_INTERNAL;
    }

    EVP_PKEY_CTX_free(pctx);

    // For EC keys, the same EVP_PKEY contains both public and private key
    EVP_PKEY_up_ref(pkey);
    *public_key = pkey;
    *private_key = pkey;

    return CRYPTO_OK;
}

crypto_error_t evp_sign_data(EVP_PKEY *private_key, const uint8_t *data, size_t data_len,
                             uint8_t *signature, size_t *signature_len)
{
    if (!private_key || !data || !signature || !signature_len)
    {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        return CRYPTO_ERROR_MEMORY;
    }

    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, private_key) <= 0)
    {
        EVP_MD_CTX_free(md_ctx);
        return CRYPTO_ERROR_INTERNAL;
    }

    // Get signature length
    size_t sig_len = 0;
    if (EVP_DigestSign(md_ctx, NULL, &sig_len, data, data_len) <= 0)
    {
        EVP_MD_CTX_free(md_ctx);
        return CRYPTO_ERROR_INTERNAL;
    }

    if (sig_len > *signature_len)
    {
        EVP_MD_CTX_free(md_ctx);
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    // Generate signature
    if (EVP_DigestSign(md_ctx, signature, &sig_len, data, data_len) <= 0)
    {
        EVP_MD_CTX_free(md_ctx);
        return CRYPTO_ERROR_INTERNAL;
    }

    *signature_len = sig_len;
    EVP_MD_CTX_free(md_ctx);
    return CRYPTO_OK;
}

crypto_error_t evp_verify_signature(EVP_PKEY *public_key, const uint8_t *data, size_t data_len,
                                    const uint8_t *signature, size_t signature_len)
{
    if (!public_key || !data || !signature)
    {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
    {
        return CRYPTO_ERROR_MEMORY;
    }

    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, public_key) <= 0)
    {
        EVP_MD_CTX_free(md_ctx);
        return CRYPTO_ERROR_INTERNAL;
    }

    int result = EVP_DigestVerify(md_ctx, signature, signature_len, data, data_len);
    EVP_MD_CTX_free(md_ctx);

    return (result == 1) ? CRYPTO_OK : CRYPTO_ERROR_INVALID_SIGNATURE;
}

crypto_error_t evp_serialize_public_key(EVP_PKEY *key, uint8_t *buffer, size_t *buffer_len)
{
    if (!key || !buffer || !buffer_len)
    {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    // For EC keys, we need to serialize the point
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(key);
    if (!ec_key)
    {
        return CRYPTO_ERROR_INTERNAL;
    }

    const EC_POINT *point = EC_KEY_get0_public_key(ec_key);
    if (!point)
    {
        EC_KEY_free(ec_key);
        return CRYPTO_ERROR_INTERNAL;
    }

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    if (!group)
    {
        EC_KEY_free(ec_key);
        return CRYPTO_ERROR_INTERNAL;
    }

    // Get the size needed for uncompressed point
    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, NULL, 0, NULL);
    if (len == 0)
    {
        EC_KEY_free(ec_key);
        return CRYPTO_ERROR_INTERNAL;
    }

    if (len > *buffer_len)
    {
        EC_KEY_free(ec_key);
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED, buffer, len, NULL) == 0)
    {
        EC_KEY_free(ec_key);
        return CRYPTO_ERROR_INTERNAL;
    }

    *buffer_len = len;
    EC_KEY_free(ec_key);
    return CRYPTO_OK;
}

crypto_error_t evp_deserialize_public_key(const uint8_t *buffer, size_t buffer_len, EVP_PKEY **key)
{
    if (!buffer || !key)
    {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    // Create EC group for P-256
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group)
    {
        return CRYPTO_ERROR_INTERNAL;
    }

    // Create EC point from buffer
    EC_POINT *point = EC_POINT_new(group);
    if (!point)
    {
        EC_GROUP_free(group);
        return CRYPTO_ERROR_INTERNAL;
    }

    if (EC_POINT_oct2point(group, point, buffer, buffer_len, NULL) == 0)
    {
        EC_POINT_free(point);
        EC_GROUP_free(group);
        return CRYPTO_ERROR_INTERNAL;
    }

    // Create EC key with the point
    EC_KEY *ec_key = EC_KEY_new();
    if (!ec_key)
    {
        EC_POINT_free(point);
        EC_GROUP_free(group);
        return CRYPTO_ERROR_INTERNAL;
    }

    if (EC_KEY_set_group(ec_key, group) == 0)
    {
        EC_KEY_free(ec_key);
        EC_POINT_free(point);
        EC_GROUP_free(group);
        return CRYPTO_ERROR_INTERNAL;
    }

    if (EC_KEY_set_public_key(ec_key, point) == 0)
    {
        EC_KEY_free(ec_key);
        EC_POINT_free(point);
        EC_GROUP_free(group);
        return CRYPTO_ERROR_INTERNAL;
    }

    // Create EVP_PKEY from EC key
    *key = EVP_PKEY_new();
    if (!*key)
    {
        EC_KEY_free(ec_key);
        EC_POINT_free(point);
        EC_GROUP_free(group);
        return CRYPTO_ERROR_INTERNAL;
    }

    if (EVP_PKEY_assign_EC_KEY(*key, ec_key) == 0)
    {
        EVP_PKEY_free(*key);
        *key = NULL;
        EC_POINT_free(point);
        EC_GROUP_free(group);
        return CRYPTO_ERROR_INTERNAL;
    }

    EC_POINT_free(point);
    EC_GROUP_free(group);
    return CRYPTO_OK;
}

crypto_error_t evp_serialize_private_key(EVP_PKEY *key, uint8_t *buffer, size_t *buffer_len)
{
    if (!key || !buffer || !buffer_len)
    {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    // For EC private keys, we need to serialize the private key
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(key);
    if (!ec_key)
    {
        return CRYPTO_ERROR_INTERNAL;
    }

    const BIGNUM *priv = EC_KEY_get0_private_key(ec_key);
    if (!priv)
    {
        EC_KEY_free(ec_key);
        return CRYPTO_ERROR_INTERNAL;
    }

    // Get the size needed for the private key
    size_t len = BN_num_bytes(priv);
    if (len == 0)
    {
        EC_KEY_free(ec_key);
        return CRYPTO_ERROR_INTERNAL;
    }

    if (len > *buffer_len)
    {
        EC_KEY_free(ec_key);
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    if (BN_bn2bin(priv, buffer) != len)
    {
        EC_KEY_free(ec_key);
        return CRYPTO_ERROR_INTERNAL;
    }

    *buffer_len = len;
    EC_KEY_free(ec_key);
    return CRYPTO_OK;
}

crypto_error_t evp_deserialize_private_key(const uint8_t *buffer, size_t buffer_len, EVP_PKEY **key)
{
    if (!buffer || !key)
    {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    // Create EC group for P-256
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group)
    {
        return CRYPTO_ERROR_INTERNAL;
    }

    // Create BIGNUM from buffer
    BIGNUM *priv = BN_bin2bn(buffer, buffer_len, NULL);
    if (!priv)
    {
        EC_GROUP_free(group);
        return CRYPTO_ERROR_INTERNAL;
    }

    // Create EC key with the private key
    EC_KEY *ec_key = EC_KEY_new();
    if (!ec_key)
    {
        BN_free(priv);
        EC_GROUP_free(group);
        return CRYPTO_ERROR_INTERNAL;
    }

    if (EC_KEY_set_group(ec_key, group) == 0)
    {
        EC_KEY_free(ec_key);
        BN_free(priv);
        EC_GROUP_free(group);
        return CRYPTO_ERROR_INTERNAL;
    }

    if (EC_KEY_set_private_key(ec_key, priv) == 0)
    {
        EC_KEY_free(ec_key);
        BN_free(priv);
        EC_GROUP_free(group);
        return CRYPTO_ERROR_INTERNAL;
    }

    // Compute public key from private key
    if (EC_KEY_generate_key(ec_key) == 0)
    {
        EC_KEY_free(ec_key);
        BN_free(priv);
        EC_GROUP_free(group);
        return CRYPTO_ERROR_INTERNAL;
    }

    // Create EVP_PKEY from EC key
    *key = EVP_PKEY_new();
    if (!*key)
    {
        EC_KEY_free(ec_key);
        BN_free(priv);
        EC_GROUP_free(group);
        return CRYPTO_ERROR_INTERNAL;
    }

    if (EVP_PKEY_assign_EC_KEY(*key, ec_key) == 0)
    {
        EVP_PKEY_free(*key);
        *key = NULL;
        BN_free(priv);
        EC_GROUP_free(group);
        return CRYPTO_ERROR_INTERNAL;
    }

    BN_free(priv);
    EC_GROUP_free(group);
    return CRYPTO_OK;
}

crypto_error_t evp_validate_key(EVP_PKEY *key)
{
    if (!key)
    {
        return CRYPTO_ERROR_INVALID_PARAMETER;
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx)
    {
        return CRYPTO_ERROR_INTERNAL;
    }
    int ret = EVP_PKEY_check(ctx);
    EVP_PKEY_CTX_free(ctx);
    if (ret <= 0)
    {
        return CRYPTO_ERROR_INVALID_KEY;
    }
    return CRYPTO_OK;
}