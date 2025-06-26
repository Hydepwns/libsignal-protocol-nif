#ifndef SESSION_H
#define SESSION_H

#include <erl_nif.h>
#include "../types.h"

// Session creation and management
ERL_NIF_TERM create_session(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM process_pre_key_bundle(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

// Message encryption/decryption
ERL_NIF_TERM encrypt_message(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM decrypt_message(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

// Session state management
void cleanup_session_state(ratchet_state_t *state);
int rotate_sending_ratchet(ratchet_state_t *state);
int rotate_receiving_ratchet(ratchet_state_t *state, EVP_PKEY *their_dh_key);

#endif // SESSION_H