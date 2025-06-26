#include <erl_nif.h>
#include <stdio.h>
#include <string.h>

// Include all modular components
#include "constants.h"
#include "types.h"
#include "utils/utils.h"
#include "utils/error_handling.h"
#include "keys/keys.h"
#include "session/session.h"
#include "cache/cache.h"
#include "crypto/crypto.h"
#include "protocol/protocol.h"

// Forward declarations for internal functions
static int generate_ec_key_pair(EVP_PKEY **key);
static ERL_NIF_TERM key_to_binary(ErlNifEnv *env, EVP_PKEY *key, int is_public);
static int generate_ed25519_key_pair_internal(EVP_PKEY **key);

// NIF function declarations
ERL_NIF_TERM generate_identity_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM generate_pre_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM generate_signed_pre_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM verify_signature(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM compute_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM generate_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM generate_curve25519_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM generate_ed25519_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM validate_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM private_to_public_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

// NIF function table
ErlNifFunc nif_funcs[] = {
    {"generate_identity_key_pair", 0, generate_identity_key_pair},
    {"generate_pre_key", 1, generate_pre_key},
    {"generate_signed_pre_key", 2, generate_signed_pre_key},
    {"create_session", 1, create_session},
    {"process_pre_key_bundle", 2, process_pre_key_bundle},
    {"encrypt_message", 2, encrypt_message},
    {"decrypt_message", 2, decrypt_message},
    {"get_cache_stats", 1, get_cache_stats},
    {"reset_cache_stats", 1, reset_cache_stats},
    {"set_cache_size", 3, set_cache_size},
    {"verify_signature", 3, verify_signature},
    {"compute_key", 2, compute_key},
    {"generate_key_pair", 0, generate_key_pair},
    {"generate_curve25519_key_pair", 0, generate_curve25519_key_pair},
    {"generate_ed25519_key_pair", 0, generate_ed25519_key_pair},
    {"validate_key_pair", 2, validate_key_pair},
    {"private_to_public_key", 1, private_to_public_key},
    {NULL, 0, NULL}};

// NIF lifecycle functions
int on_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
  fprintf(stderr, "[NIF DEBUG] on_load: Initializing libsignal-protocol-nif\n");

  // Print all NIF function names and arities
  size_t num_funcs = sizeof(nif_funcs) / sizeof(ErlNifFunc);
  for (size_t i = 0; i < num_funcs; ++i)
  {
    if (nif_funcs[i].name != NULL)
      fprintf(stderr, "[NIF DEBUG] NIF function: %s/%d\n", nif_funcs[i].name, nif_funcs[i].arity);
  }

  // Initialize OpenSSL
  if (!init_openssl())
  {
    fprintf(stderr, "[NIF DEBUG] on_load: Failed to initialize OpenSSL\n");
    return -1;
  }

  fprintf(stderr, "[NIF DEBUG] on_load: Initialization successful\n");
  return 0;
}

void on_unload(ErlNifEnv *env, void *priv_data)
{
  fprintf(stderr, "[NIF DEBUG] on_unload: Cleaning up libsignal-protocol-nif\n");
  cleanup_openssl();
}

// Internal function implementations
static int generate_ec_key_pair(EVP_PKEY **key)
{
  EVP_PKEY *public_key = NULL, *private_key = NULL;
  fprintf(stderr, "[NIF DEBUG] generate_ec_key_pair: calling curve25519_generate_keypair\n");

  // Use Curve25519 instead of P-256
  curve25519_key_t pub_key, priv_key;
  crypto_error_t result = curve25519_generate_keypair(&pub_key, &priv_key);
  fprintf(stderr, "[NIF DEBUG] generate_ec_key_pair: curve25519_generate_keypair result = %d\n", result);
  if (result != CRYPTO_OK)
  {
    fprintf(stderr, "[NIF DEBUG] generate_ec_key_pair: key generation failed\n");
    return 0;
  }

  // Create EVP_PKEY from Curve25519 private key
  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv_key.key, CURVE25519_KEY_SIZE);
  if (!pkey)
  {
    fprintf(stderr, "[NIF DEBUG] generate_ec_key_pair: failed to create EVP_PKEY\n");
    return 0;
  }

  *key = pkey;
  fprintf(stderr, "[NIF DEBUG] generate_ec_key_pair: key generation succeeded\n");
  return 1;
}

static int generate_ed25519_key_pair_internal(EVP_PKEY **key)
{
  fprintf(stderr, "[NIF DEBUG] generate_ed25519_key_pair_internal: generating Ed25519 key pair\n");

  // Create EVP_PKEY context for Ed25519 key generation
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
  if (!pctx)
  {
    fprintf(stderr, "[NIF DEBUG] generate_ed25519_key_pair_internal: failed to create context\n");
    return 0;
  }

  if (EVP_PKEY_keygen_init(pctx) <= 0)
  {
    fprintf(stderr, "[NIF DEBUG] generate_ed25519_key_pair_internal: failed to init keygen\n");
    EVP_PKEY_CTX_free(pctx);
    return 0;
  }

  EVP_PKEY *pkey = NULL;
  if (EVP_PKEY_keygen(pctx, &pkey) <= 0)
  {
    fprintf(stderr, "[NIF DEBUG] generate_ed25519_key_pair_internal: failed to generate key\n");
    EVP_PKEY_CTX_free(pctx);
    return 0;
  }

  EVP_PKEY_CTX_free(pctx);
  *key = pkey;
  fprintf(stderr, "[NIF DEBUG] generate_ed25519_key_pair_internal: key generation succeeded\n");
  return 1;
}

static ERL_NIF_TERM key_to_binary(ErlNifEnv *env, EVP_PKEY *key, int is_public)
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
      fprintf(stderr, "[NIF DEBUG] key_to_binary: serializing Curve25519 public key\n");

      if (EVP_PKEY_get_raw_public_key(key, buffer, &buffer_len) <= 0 || buffer_len != CURVE25519_KEY_SIZE)
      {
        fprintf(stderr, "[NIF DEBUG] key_to_binary: failed to get raw public key\n");
        return make_error(env, "Failed to serialize public key");
      }

      return make_binary(env, buffer, buffer_len);
    }
    else
    {
      // For Curve25519 private key, extract raw private key
      uint8_t buffer[CURVE25519_KEY_SIZE];
      size_t buffer_len = sizeof(buffer);
      fprintf(stderr, "[NIF DEBUG] key_to_binary: serializing Curve25519 private key\n");

      if (EVP_PKEY_get_raw_private_key(key, buffer, &buffer_len) <= 0 || buffer_len != CURVE25519_KEY_SIZE)
      {
        fprintf(stderr, "[NIF DEBUG] key_to_binary: failed to get raw private key\n");
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
      fprintf(stderr, "[NIF DEBUG] key_to_binary: serializing Ed25519 public key\n");

      if (EVP_PKEY_get_raw_public_key(key, buffer, &buffer_len) <= 0 || buffer_len != CURVE25519_KEY_SIZE)
      {
        fprintf(stderr, "[NIF DEBUG] key_to_binary: failed to get raw Ed25519 public key\n");
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
      fprintf(stderr, "[NIF DEBUG] key_to_binary: serializing Ed25519 private key (64-byte format)\n");

      if (EVP_PKEY_get_raw_private_key(key, private_buffer, &private_len) <= 0 || private_len != CURVE25519_KEY_SIZE)
      {
        fprintf(stderr, "[NIF DEBUG] key_to_binary: failed to get raw Ed25519 private key\n");
        return make_error(env, "Failed to serialize Ed25519 private key");
      }

      if (EVP_PKEY_get_raw_public_key(key, public_buffer, &public_len) <= 0 || public_len != CURVE25519_KEY_SIZE)
      {
        fprintf(stderr, "[NIF DEBUG] key_to_binary: failed to get raw Ed25519 public key\n");
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
    fprintf(stderr, "[NIF DEBUG] key_to_binary: unsupported key type %d\n", key_type);
    return make_error(env, "Unsupported key type");
  }
}

// NIF function implementations that delegate to modular components
ERL_NIF_TERM generate_identity_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  return generate_ed25519_key_pair(env, argc, argv);
}

ERL_NIF_TERM generate_pre_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  if (argc != 1)
  {
    return enif_make_badarg(env);
  }

  // Parse the key ID argument
  int key_id;
  if (!enif_get_int(env, argv[0], &key_id))
  {
    return make_error(env, "Invalid key ID");
  }

  // Generate the key pair directly using the crypto function
  curve25519_key_t public_key, private_key;
  crypto_error_t result = curve25519_generate_keypair(&public_key, &private_key);

  if (result != CRYPTO_OK)
  {
    return make_error(env, "Failed to generate key pair");
  }

  // Create the result: {ok, {KeyId, PublicKey}}
  ERL_NIF_TERM key_id_term = enif_make_int(env, key_id);
  ERL_NIF_TERM public_key_term = make_binary(env, public_key.key, CURVE25519_KEY_SIZE);

  return make_ok(env, enif_make_tuple2(env, key_id_term, public_key_term));
}

ERL_NIF_TERM generate_signed_pre_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  if (argc != 2)
  {
    return enif_make_badarg(env);
  }

  // Parse the arguments: identity_key, key_id
  ErlNifBinary identity_key_bin;
  int key_id;
  if (!enif_inspect_binary(env, argv[0], &identity_key_bin) ||
      !enif_get_int(env, argv[1], &key_id))
  {
    return make_error(env, "Invalid arguments");
  }

  // Generate Ed25519 key pair for signing
  EVP_PKEY *private_key = NULL, *public_key = NULL;
  if (!generate_ed25519_key_pair_internal(&private_key))
  {
    return make_error(env, "Failed to generate Ed25519 key pair");
  }

  // Create a signed pre-key bundle
  protocol_signed_pre_key_t signed_pre_key;
  signed_pre_key.key_id = key_id;

  // Extract the public key bytes
  uint8_t pub_key_bytes[CURVE25519_KEY_SIZE];
  size_t pub_key_len = sizeof(pub_key_bytes);
  if (EVP_PKEY_get_raw_public_key(private_key, pub_key_bytes, &pub_key_len) <= 0)
  {
    EVP_PKEY_free(private_key);
    return make_error(env, "Failed to extract public key");
  }

  // Copy to the signed pre-key structure
  memcpy(signed_pre_key.key.key, pub_key_bytes, CURVE25519_KEY_SIZE);

  // Sign the pre-key with the identity key (for now, just use the same key)
  // In a real implementation, you'd use a separate identity key
  uint8_t signature[64];
  size_t signature_len = sizeof(signature);
  if (evp_sign_data(private_key, pub_key_bytes, CURVE25519_KEY_SIZE,
                    signature, &signature_len) != CRYPTO_OK)
  {
    EVP_PKEY_free(private_key);
    return make_error(env, "Failed to sign pre-key");
  }

  memcpy(signed_pre_key.signature, signature, 64);

  // Create the result tuple: {ok, {KeyId, PublicKey, Signature}}
  ERL_NIF_TERM key_id_term = enif_make_int(env, key_id);
  ERL_NIF_TERM public_key_term = make_binary(env, pub_key_bytes, CURVE25519_KEY_SIZE);
  ERL_NIF_TERM signature_term = make_binary(env, signature, 64);

  EVP_PKEY_free(private_key);
  return make_ok(env, enif_make_tuple3(env, key_id_term, public_key_term, signature_term));
}

ERL_NIF_TERM verify_signature(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  if (argc != 3)
  {
    return make_error(env, "verify_signature requires 3 arguments");
  }

  // Parse the arguments: public_key, data, signature
  ErlNifBinary public_key_bin, data_bin, signature_bin;
  if (!enif_inspect_binary(env, argv[0], &public_key_bin) ||
      !enif_inspect_binary(env, argv[1], &data_bin) ||
      !enif_inspect_binary(env, argv[2], &signature_bin))
  {
    return make_error(env, "Invalid binary arguments");
  }

  // Create EVP_PKEY from public key
  EVP_PKEY *public_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
                                                     public_key_bin.data, public_key_bin.size);
  if (!public_key)
  {
    return make_error(env, "Failed to create public key");
  }

  // Verify the signature
  crypto_error_t result = evp_verify_signature(public_key, data_bin.data, data_bin.size,
                                               signature_bin.data, signature_bin.size);
  EVP_PKEY_free(public_key);

  if (result != CRYPTO_OK)
  {
    return make_error(env, "Signature verification failed");
  }

  return make_ok(env, enif_make_atom(env, "verified"));
}

ERL_NIF_TERM compute_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  if (argc != 2)
  {
    return make_error(env, "compute_key requires 2 arguments");
  }

  // Parse the arguments: private_key, public_key
  ErlNifBinary private_key_bin, public_key_bin;
  if (!enif_inspect_binary(env, argv[0], &private_key_bin) ||
      !enif_inspect_binary(env, argv[1], &public_key_bin))
  {
    return make_error(env, "Invalid binary arguments");
  }

  // Create EVP_PKEY objects
  EVP_PKEY *private_key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                       private_key_bin.data, private_key_bin.size);
  EVP_PKEY *public_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                                     public_key_bin.data, public_key_bin.size);

  if (!private_key || !public_key)
  {
    if (private_key)
      EVP_PKEY_free(private_key);
    if (public_key)
      EVP_PKEY_free(public_key);
    return make_error(env, "Failed to create key objects");
  }

  // Compute shared secret
  unsigned char shared_secret[32];
  size_t shared_secret_len = sizeof(shared_secret);
  crypto_error_t result = evp_compute_shared_secret(private_key, public_key,
                                                    shared_secret, &shared_secret_len);

  EVP_PKEY_free(private_key);
  EVP_PKEY_free(public_key);

  if (result != CRYPTO_OK)
  {
    return make_error(env, "Failed to compute shared secret");
  }

  return make_ok(env, make_binary(env, shared_secret, shared_secret_len));
}

// NIF module definition
ERL_NIF_INIT(nif, nif_funcs, on_load, NULL, NULL, on_unload)