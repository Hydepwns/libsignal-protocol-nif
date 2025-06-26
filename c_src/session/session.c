#include "session.h"
#include "../constants.h"
#include "../types.h"
#include "../utils/utils.h"
#include "../utils/error_handling.h"
#include "../keys/keys.h"
#include "../crypto/crypto.h"
#include <string.h>
#include <openssl/rand.h>

// Helper functions
static int parse_uint32(const unsigned char *data, uint32_t *value)
{
  if (!data || !value)
    return 0;
  *value = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
  return 1;
}

static int parse_binary(const unsigned char *data, size_t data_len, size_t *offset,
                        unsigned char **binary, size_t *binary_len)
{
  if (*offset + 4 > data_len)
    return 0;

  uint32_t len;
  if (!parse_uint32(data + *offset, &len))
    return 0;
  *offset += 4;

  if (*offset + len > data_len)
    return 0;

  *binary = (unsigned char *)(data + *offset);
  *binary_len = len;
  *offset += len;
  return 1;
}

static int calculate_dh_shared_secret(EVP_PKEY *our_key, EVP_PKEY *their_key,
                                      unsigned char *shared_secret, size_t *shared_secret_len)
{
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(our_key, NULL);
  if (!ctx)
    return 0;

  if (EVP_PKEY_derive_init(ctx) <= 0)
  {
    EVP_PKEY_CTX_free(ctx);
    return 0;
  }

  if (EVP_PKEY_derive_set_peer(ctx, their_key) <= 0)
  {
    EVP_PKEY_CTX_free(ctx);
    return 0;
  }

  if (EVP_PKEY_derive(ctx, shared_secret, shared_secret_len) <= 0)
  {
    EVP_PKEY_CTX_free(ctx);
    return 0;
  }

  EVP_PKEY_CTX_free(ctx);
  return 1;
}

static int derive_root_key(const unsigned char *dh_output, size_t dh_output_len,
                           const unsigned char *salt, size_t salt_len,
                           unsigned char *root_key)
{
  return evp_derive_key(dh_output, dh_output_len, salt, salt_len, root_key, ROOT_KEY_LEN);
}

static int derive_chain_key(const unsigned char *root_key, size_t root_key_len,
                            const unsigned char *salt, size_t salt_len,
                            unsigned char *chain_key)
{
  return evp_derive_key(root_key, root_key_len, salt, salt_len, chain_key, CHAIN_KEY_LEN);
}

static int generate_ec_key_pair(EVP_PKEY **key)
{
  curve25519_key_t pub_key, priv_key;
  crypto_error_t result = curve25519_generate_keypair(&pub_key, &priv_key);
  if (result != CRYPTO_OK)
  {
    return 0;
  }
  EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, priv_key.key, CURVE25519_KEY_SIZE);
  if (!pkey)
  {
    return 0;
  }
  *key = pkey;
  return 1;
}

// Session management functions
ERL_NIF_TERM create_session(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  if (argc != 1)
  {
    return enif_make_badarg(env);
  }

  // Parse the identity key argument
  ErlNifBinary identity_key_bin;
  if (!enif_inspect_binary(env, argv[0], &identity_key_bin))
  {
    return make_error(env, "Invalid identity key");
  }

  // Generate a unique session ID
  unsigned char id[32];
  if (!RAND_bytes(id, sizeof(id)))
  {
    return make_error(env, "Failed to generate session ID");
  }

  // Create the session structure: {SessionId, IdentityKey}
  ERL_NIF_TERM session_id = make_binary(env, id, sizeof(id));
  ERL_NIF_TERM identity_key = make_binary(env, identity_key_bin.data, identity_key_bin.size);

  return make_ok(env, enif_make_tuple2(env, session_id, identity_key));
}

ERL_NIF_TERM process_pre_key_bundle(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  if (argc != 2)
  {
    return enif_make_badarg(env);
  }

  ErlNifBinary session, bundle;
  if (!enif_inspect_binary(env, argv[0], &session) ||
      !enif_inspect_binary(env, argv[1], &bundle))
  {
    return make_error(env, "Invalid arguments");
  }

  // Parse bundle components
  size_t offset = 0;
  uint32_t registration_id, device_id, pre_key_id, signed_pre_key_id;
  unsigned char *pre_key = NULL, *signed_pre_key = NULL, *identity_key = NULL;
  size_t pre_key_len = 0, signed_pre_key_len = 0, identity_key_len = 0;

  // Parse registration ID
  if (!parse_uint32(bundle.data + offset, &registration_id))
  {
    return make_error(env, "Invalid registration ID");
  }
  offset += 4;

  // Parse device ID
  if (!parse_uint32(bundle.data + offset, &device_id))
  {
    return make_error(env, "Invalid device ID");
  }
  offset += 4;

  // Parse pre-key ID
  if (!parse_uint32(bundle.data + offset, &pre_key_id))
  {
    return make_error(env, "Invalid pre-key ID");
  }
  offset += 4;

  // Parse pre-key
  if (!parse_binary(bundle.data, bundle.size, &offset, &pre_key, &pre_key_len))
  {
    return make_error(env, "Invalid pre-key");
  }

  // Parse signed pre-key ID
  if (!parse_uint32(bundle.data + offset, &signed_pre_key_id))
  {
    return make_error(env, "Invalid signed pre-key ID");
  }
  offset += 4;

  // Parse signed pre-key
  if (!parse_binary(bundle.data, bundle.size, &offset, &signed_pre_key, &signed_pre_key_len))
  {
    return make_error(env, "Invalid signed pre-key");
  }

  // Parse identity key
  if (!parse_binary(bundle.data, bundle.size, &offset, &identity_key, &identity_key_len))
  {
    return make_error(env, "Invalid identity key");
  }

  // Verify we've consumed all data
  if (offset != bundle.size)
  {
    return make_error(env, "Extra data in bundle");
  }

  // Create EVP_PKEY objects
  EVP_PKEY *pre_key_ec = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, pre_key, pre_key_len);
  EVP_PKEY *signed_pre_key_ec = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, signed_pre_key, signed_pre_key_len);
  EVP_PKEY *identity_key_ec = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, identity_key, identity_key_len);

  if (!pre_key_ec || !signed_pre_key_ec || !identity_key_ec)
  {
    if (pre_key_ec)
      EVP_PKEY_free(pre_key_ec);
    if (signed_pre_key_ec)
      EVP_PKEY_free(signed_pre_key_ec);
    if (identity_key_ec)
      EVP_PKEY_free(identity_key_ec);
    return make_error(env, "Failed to create EVP_PKEY objects");
  }

  // Generate ephemeral key pair
  EVP_PKEY *ephemeral_key = NULL;
  if (!generate_ec_key_pair(&ephemeral_key))
  {
    EVP_PKEY_free(identity_key_ec);
    EVP_PKEY_free(signed_pre_key_ec);
    EVP_PKEY_free(pre_key_ec);
    return make_error(env, "Failed to generate ephemeral key");
  }

  // Calculate shared secrets
  unsigned char dh1[256], dh2[256], dh3[256];
  size_t dh1_len = sizeof(dh1), dh2_len = sizeof(dh2), dh3_len = sizeof(dh3);

  if (!calculate_dh_shared_secret(ephemeral_key, pre_key_ec, dh1, &dh1_len) ||
      !calculate_dh_shared_secret(ephemeral_key, signed_pre_key_ec, dh2, &dh2_len) ||
      !calculate_dh_shared_secret(ephemeral_key, identity_key_ec, dh3, &dh3_len))
  {
    EVP_PKEY_free(ephemeral_key);
    EVP_PKEY_free(identity_key_ec);
    EVP_PKEY_free(signed_pre_key_ec);
    EVP_PKEY_free(pre_key_ec);
    return make_error(env, "Failed to calculate shared secrets");
  }

  // Derive master secret
  unsigned char master_secret[96];
  memcpy(master_secret, dh1, dh1_len);
  memcpy(master_secret + dh1_len, dh2, dh2_len);
  memcpy(master_secret + dh1_len + dh2_len, dh3, dh3_len);

  // Derive root key
  unsigned char root_key[ROOT_KEY_LEN];
  if (!derive_root_key(master_secret, sizeof(master_secret), NULL, 0, root_key))
  {
    EVP_PKEY_free(ephemeral_key);
    EVP_PKEY_free(identity_key_ec);
    EVP_PKEY_free(signed_pre_key_ec);
    EVP_PKEY_free(pre_key_ec);
    return make_error(env, "Failed to derive root key");
  }

  // Derive chain key
  unsigned char chain_key[CHAIN_KEY_LEN];
  if (!derive_chain_key(root_key, ROOT_KEY_LEN, NULL, 0, chain_key))
  {
    EVP_PKEY_free(ephemeral_key);
    EVP_PKEY_free(identity_key_ec);
    EVP_PKEY_free(signed_pre_key_ec);
    EVP_PKEY_free(pre_key_ec);
    return make_error(env, "Failed to derive chain key");
  }

  // Create a simple session state
  simple_session_t session_state;
  memset(&session_state, 0, sizeof(simple_session_t));

  // Initialize session state with derived keys
  memcpy(session_state.root_key, root_key, ROOT_KEY_LEN);
  memcpy(session_state.sending_chain_key, chain_key, CHAIN_KEY_LEN);
  session_state.sending_chain_index = 0;
  session_state.sending_ratchet_index = 0;
  session_state.receiving_ratchet_index = 0;

  // Store ephemeral key as raw bytes
  size_t ephemeral_key_len = CURVE25519_KEY_SIZE;
  if (EVP_PKEY_get_raw_public_key(ephemeral_key, session_state.ephemeral_key, &ephemeral_key_len) <= 0)
  {
    EVP_PKEY_free(ephemeral_key);
    EVP_PKEY_free(identity_key_ec);
    EVP_PKEY_free(signed_pre_key_ec);
    EVP_PKEY_free(pre_key_ec);
    return make_error(env, "Failed to serialize ephemeral key");
  }

  // Serialize session state to binary
  ERL_NIF_TERM session_binary = make_binary(env, (unsigned char *)&session_state, sizeof(simple_session_t));

  // Clean up
  EVP_PKEY_free(ephemeral_key);
  EVP_PKEY_free(identity_key_ec);
  EVP_PKEY_free(signed_pre_key_ec);
  EVP_PKEY_free(pre_key_ec);

  return make_ok(env, session_binary);
}

ERL_NIF_TERM encrypt_message(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  if (argc != 2)
  {
    return enif_make_badarg(env);
  }

  ErlNifBinary session, message;
  if (!enif_inspect_binary(env, argv[0], &session) ||
      !enif_inspect_binary(env, argv[1], &message))
  {
    return make_error(env, "Invalid arguments");
  }

  // Extract simple session state from session
  simple_session_t session_state;
  if (session.size < sizeof(simple_session_t))
  {
    return make_error(env, "Invalid session data");
  }
  memcpy(&session_state, session.data, sizeof(simple_session_t));

  // For now, just return a simple encrypted message
  // In a real implementation, this would do proper ratchet encryption
  unsigned char encrypted_data[message.size + 16]; // message + IV + tag
  memcpy(encrypted_data, message.data, message.size);

  // Generate random IV
  if (!RAND_bytes(encrypted_data + message.size, 16))
  {
    return make_error(env, "Failed to generate IV");
  }

  ERL_NIF_TERM encrypted_binary = make_binary(env, encrypted_data, message.size + 16);
  return make_ok(env, encrypted_binary);
}

ERL_NIF_TERM decrypt_message(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  if (argc != 2)
  {
    return enif_make_badarg(env);
  }

  ErlNifBinary session, encrypted_message;
  if (!enif_inspect_binary(env, argv[0], &session) ||
      !enif_inspect_binary(env, argv[1], &encrypted_message))
  {
    return make_error(env, "Invalid arguments");
  }

  // Extract simple session state from session
  simple_session_t session_state;
  if (session.size < sizeof(simple_session_t))
  {
    return make_error(env, "Invalid session data");
  }
  memcpy(&session_state, session.data, sizeof(simple_session_t));

  // For now, just return the decrypted message (simple implementation)
  // In a real implementation, this would do proper ratchet decryption
  if (encrypted_message.size < 16)
  {
    return make_error(env, "Invalid encrypted message size");
  }

  size_t message_size = encrypted_message.size - 16;
  ERL_NIF_TERM decrypted_binary = make_binary(env, encrypted_message.data, message_size);
  return make_ok(env, decrypted_binary);
}

// Session state management functions
void cleanup_session_state(ratchet_state_t *state)
{
  if (!state)
    return;

  // Clean up EVP_PKEY objects
  if (state->sending_chain.dh_key)
  {
    EVP_PKEY_free(state->sending_chain.dh_key);
    state->sending_chain.dh_key = NULL;
  }
  if (state->receiving_chain.dh_key)
  {
    EVP_PKEY_free(state->receiving_chain.dh_key);
    state->receiving_chain.dh_key = NULL;
  }

  // Clean up cache arrays
  if (state->chain_key_cache)
  {
    free(state->chain_key_cache);
    state->chain_key_cache = NULL;
  }
  if (state->root_key_cache)
  {
    free(state->root_key_cache);
    state->root_key_cache = NULL;
  }
}

int rotate_sending_ratchet(ratchet_state_t *state)
{
  if (!state)
    return 0;

  // Generate new DH key pair
  EVP_PKEY *new_dh_key = NULL;
  if (!generate_ec_key_pair(&new_dh_key))
  {
    return 0;
  }

  // Clean up old key
  if (state->sending_chain.dh_key)
  {
    EVP_PKEY_free(state->sending_chain.dh_key);
  }

  // Set new key
  state->sending_chain.dh_key = new_dh_key;
  state->sending_ratchet_index++;

  return 1;
}

int rotate_receiving_ratchet(ratchet_state_t *state, EVP_PKEY *their_dh_key)
{
  if (!state || !their_dh_key)
    return 0;

  // Set their DH key
  if (state->receiving_chain.dh_key)
  {
    EVP_PKEY_free(state->receiving_chain.dh_key);
  }
  EVP_PKEY_up_ref(their_dh_key);
  state->receiving_chain.dh_key = their_dh_key;
  state->receiving_ratchet_index++;

  return 1;
}