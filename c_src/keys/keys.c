#include "keys.h"
#include "../constants.h"
#include "../types.h"
#include "../utils/utils.h"
#include "../utils/error_handling.h"
#include "../crypto/crypto.h"
#include <string.h>

// Key validation functions
int validate_public_key(const unsigned char *key_data, size_t key_len)
{
  if (!key_data || key_len != CURVE25519_KEY_SIZE)
  {
    return 0;
  }

  // Create EVP_PKEY from raw public key data
  EVP_PKEY *key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, key_data, key_len);
  if (!key)
  {
    return 0;
  }

  // Validate the key
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
  if (!ctx)
  {
    EVP_PKEY_free(key);
    return 0;
  }

  int result = EVP_PKEY_public_check(ctx);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(key);

  return result > 0;
}

int validate_private_key(const unsigned char *key_data, size_t key_len)
{
  if (!key_data || key_len != CURVE25519_KEY_SIZE)
  {
    return 0;
  }

  // Create EVP_PKEY from raw private key data
  EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, key_data, key_len);
  if (!key)
  {
    return 0;
  }

  // Validate the key
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key, NULL);
  if (!ctx)
  {
    EVP_PKEY_free(key);
    return 0;
  }

  int result = EVP_PKEY_private_check(ctx);
  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(key);

  return result > 0;
}

// Key generation functions
int generate_ec_key_pair(EVP_PKEY **key)
{
  EVP_PKEY *public_key = NULL, *private_key = NULL;
  // Use Curve25519 instead of P-256
  curve25519_key_t pub_key, priv_key;
  crypto_error_t result = curve25519_generate_keypair(&pub_key, &priv_key);
  if (result != CRYPTO_OK)
  {
    return 0;
  }

  // Create EVP_PKEY from Curve25519 private key
  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv_key.key, CURVE25519_KEY_SIZE);
  if (!pkey)
  {
    return 0;
  }

  *key = pkey;
  return 1;
}

static int generate_ed25519_keypair_internal(EVP_PKEY **key)
{
  // Create EVP_PKEY context for Ed25519 key generation
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
  if (!pctx)
  {
    return 0;
  }

  if (EVP_PKEY_keygen_init(pctx) <= 0)
  {
    EVP_PKEY_CTX_free(pctx);
    return 0;
  }

  EVP_PKEY *pkey = NULL;
  if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
  {
    EVP_PKEY_CTX_free(pctx);
    return 0;
  }

  EVP_PKEY_CTX_free(pctx);
  *key = pkey;
  return 1;
}

// Key conversion functions
ERL_NIF_TERM key_to_binary(ErlNifEnv *env, EVP_PKEY *key, int is_public)
{
  int key_type = EVP_PKEY_id(key);

  if (key_type == EVP_PKEY_X25519)
  {
    // Handle X25519 keys (for key exchange)
    if (is_public)
    {
      // For Curve25519 public key, extract raw public key
      uint8_t buffer[CURVE25519_KEY_SIZE];
      size_t buffer_len = sizeof(buffer);

      if (EVP_PKEY_get_raw_public_key(key, buffer, &buffer_len) <= 0 || buffer_len != CURVE25519_KEY_SIZE)
      {
        return make_error(env, "Failed to serialize public key");
      }

      return make_binary(env, buffer, buffer_len);
    }
    else
    {
      // For Curve25519 private key, extract raw private key
      uint8_t buffer[CURVE25519_KEY_SIZE];
      size_t buffer_len = sizeof(buffer);

      if (EVP_PKEY_get_raw_private_key(key, buffer, &buffer_len) <= 0 || buffer_len != CURVE25519_KEY_SIZE)
      {
        return make_error(env, "Failed to serialize private key");
      }

      return make_binary(env, buffer, buffer_len);
    }
  }
  else if (key_type == EVP_PKEY_ED25519)
  {
    // Handle Ed25519 keys (for signing)
    if (is_public)
    {
      // For Ed25519 public key, extract raw public key
      uint8_t buffer[CURVE25519_KEY_SIZE];
      size_t buffer_len = sizeof(buffer);

      if (EVP_PKEY_get_raw_public_key(key, buffer, &buffer_len) <= 0 || buffer_len != CURVE25519_KEY_SIZE)
      {
        return make_error(env, "Failed to serialize Ed25519 public key");
      }

      return make_binary(env, buffer, buffer_len);
    }
    else
    {
      // For Ed25519 private key, extract raw private key and public key
      // Erlang's crypto:sign/verify expects 64-byte private key (private + public concatenated)
      uint8_t private_buffer[CURVE25519_KEY_SIZE];
      uint8_t public_buffer[CURVE25519_KEY_SIZE];
      uint8_t combined_buffer[CURVE25519_KEY_SIZE * 2]; // 64 bytes
      size_t private_len = sizeof(private_buffer);
      size_t public_len = sizeof(public_buffer);

      if (EVP_PKEY_get_raw_private_key(key, private_buffer, &private_len) <= 0 || private_len != CURVE25519_KEY_SIZE)
      {
        return make_error(env, "Failed to serialize Ed25519 private key");
      }

      if (EVP_PKEY_get_raw_public_key(key, public_buffer, &public_len) <= 0 || public_len != CURVE25519_KEY_SIZE)
      {
        return make_error(env, "Failed to serialize Ed25519 public key");
      }

      // Concatenate private key (32 bytes) + public key (32 bytes) = 64 bytes
      memcpy(combined_buffer, private_buffer, CURVE25519_KEY_SIZE);
      memcpy(combined_buffer + CURVE25519_KEY_SIZE, public_buffer, CURVE25519_KEY_SIZE);

      return make_binary(env, combined_buffer, CURVE25519_KEY_SIZE * 2);
    }
  }
  else
  {
    return make_error(env, "Unsupported key type");
  }
}

// NIF function implementations
ERL_NIF_TERM generate_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  if (argc != 0)
  {
    return enif_make_badarg(env);
  }

  EVP_PKEY *key = NULL;
  if (!generate_ec_key_pair(&key))
  {
    return make_error(env, "Failed to generate key pair");
  }

  ERL_NIF_TERM private_key = key_to_binary(env, key, 0);
  ERL_NIF_TERM public_key = key_to_binary(env, key, 1);
  EVP_PKEY_free(key);

  if (enif_is_exception(env, private_key) || enif_is_exception(env, public_key))
  {
    return enif_is_exception(env, private_key) ? private_key : public_key;
  }

  return make_ok(env, enif_make_tuple2(env, private_key, public_key));
}

ERL_NIF_TERM generate_curve25519_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  return generate_key_pair(env, argc, argv);
}

ERL_NIF_TERM generate_ed25519_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  if (argc != 0)
  {
    return enif_make_badarg(env);
  }

  EVP_PKEY *key = NULL;
  if (!generate_ed25519_keypair_internal(&key))
  {
    return make_error(env, "Failed to generate Ed25519 key pair");
  }

  ERL_NIF_TERM private_key = key_to_binary(env, key, 0);
  ERL_NIF_TERM public_key = key_to_binary(env, key, 1);
  EVP_PKEY_free(key);

  if (enif_is_exception(env, private_key) || enif_is_exception(env, public_key))
  {
    return enif_is_exception(env, private_key) ? private_key : public_key;
  }

  return make_ok(env, enif_make_tuple2(env, private_key, public_key));
}

ERL_NIF_TERM validate_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  if (argc != 2)
  {
    return enif_make_badarg(env);
  }

  ErlNifBinary private_bin, public_bin;
  if (!enif_inspect_binary(env, argv[0], &private_bin) ||
      !enif_inspect_binary(env, argv[1], &public_bin))
  {
    return make_error(env, "Invalid binary arguments");
  }

  int private_valid = validate_private_key(private_bin.data, private_bin.size);
  int public_valid = validate_public_key(public_bin.data, public_bin.size);

  if (!private_valid || !public_valid)
  {
    return make_error(env, "Invalid key pair");
  }

  return make_ok(env, enif_make_atom(env, "true"));
}

ERL_NIF_TERM private_to_public_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  if (argc != 1)
  {
    return enif_make_badarg(env);
  }

  ErlNifBinary private_bin;
  if (!enif_inspect_binary(env, argv[0], &private_bin))
  {
    return make_error(env, "Invalid private key binary");
  }

  // Create EVP_PKEY from private key
  EVP_PKEY *key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, private_bin.data, private_bin.size);
  if (!key)
  {
    return make_error(env, "Failed to create key from private key");
  }

  ERL_NIF_TERM public_key = key_to_binary(env, key, 1);
  EVP_PKEY_free(key);

  if (enif_is_exception(env, public_key))
  {
    return public_key;
  }

  return make_ok(env, public_key);
}