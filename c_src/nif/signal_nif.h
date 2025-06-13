#ifndef SIGNAL_NIF_H
#define SIGNAL_NIF_H

#include <erl_nif.h>
#include <signal_protocol.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/objects.h>

typedef struct {
    signal_protocol_store_t* store;
} signal_store_resource_t;

typedef struct {
    signal_session_state_t* session;
} signal_session_resource_t;

#endif // SIGNAL_NIF_H 