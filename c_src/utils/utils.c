#include "utils.h"
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

ERL_NIF_TERM make_error(ErlNifEnv *env, const char *reason)
{
  return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_string(env, reason, ERL_NIF_LATIN1));
}

ERL_NIF_TERM make_ok(ErlNifEnv *env, ERL_NIF_TERM value)
{
  return enif_make_tuple2(env, enif_make_atom(env, "ok"), value);
}

ERL_NIF_TERM make_binary(ErlNifEnv *env, const unsigned char *data, size_t len)
{
  ERL_NIF_TERM binary;
  unsigned char *binary_data = enif_make_new_binary(env, len, &binary);
  memcpy(binary_data, data, len);
  return binary;
}

int init_openssl(void)
{
  // Initialize OpenSSL
  if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL))
  {
    return 0;
  }

  // Seed the random number generator
  if (!RAND_poll())
  {
    return 0;
  }

  return 1;
}

void cleanup_openssl(void)
{
  // OpenSSL cleanup is handled automatically in modern versions
  // This function is kept for potential future use
}