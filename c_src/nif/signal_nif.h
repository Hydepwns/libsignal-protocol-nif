#ifndef SIGNAL_NIF_H
#define SIGNAL_NIF_H

#include <erl_nif.h>
#include "../protocol/signal_protocol.h"
#include <openssl/evp.h>
#include "../crypto/crypto.h"

// Forward declarations for functions used in signal_nif.c
ERL_NIF_TERM sign_data(ErlNifEnv *env, EVP_PKEY *key, const uint8_t *data, size_t data_len);
int verify_signature(EVP_PKEY *key, const uint8_t *data, size_t data_len,
                     const uint8_t *signature, size_t signature_len);

typedef struct
{
    signal_protocol_store_t *store;
} signal_store_resource_t;

typedef struct
{
    signal_session_state_t *session;
} signal_session_resource_t;

#endif // SIGNAL_NIF_H