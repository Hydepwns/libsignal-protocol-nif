#ifndef UTILS_H
#define UTILS_H

#include <erl_nif.h>

// Common utility functions
ERL_NIF_TERM make_error(ErlNifEnv *env, const char *reason);
ERL_NIF_TERM make_ok(ErlNifEnv *env, ERL_NIF_TERM value);
ERL_NIF_TERM make_binary(ErlNifEnv *env, const unsigned char *data, size_t len);

// OpenSSL initialization and cleanup
int init_openssl(void);
void cleanup_openssl(void);

#endif // UTILS_H