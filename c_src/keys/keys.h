#ifndef KEYS_H
#define KEYS_H

#include <erl_nif.h>
#include <openssl/evp.h>

// Key generation functions
ERL_NIF_TERM generate_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM generate_curve25519_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM generate_ed25519_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

// Key validation functions
int validate_public_key(const unsigned char *key_data, size_t key_len);
int validate_private_key(const unsigned char *key_data, size_t key_len);
ERL_NIF_TERM validate_key_pair(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

// Key conversion functions
ERL_NIF_TERM private_to_public_key(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

#endif // KEYS_H