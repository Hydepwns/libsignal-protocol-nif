#ifndef CACHE_H
#define CACHE_H

#include <erl_nif.h>
#include "../types.h"

// Cache statistics and management
ERL_NIF_TERM get_cache_stats(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM reset_cache_stats(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM set_cache_size(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]);

// Cache operations
void update_cache_stats(cache_stats_t *stats, int hit);
void adjust_cache_size(cache_stats_t *stats, size_t *cache_size);
int get_cached_chain_key(ratchet_state_t *state, uint32_t index, uint32_t ratchet_index, unsigned char *chain_key);
void add_chain_key_to_cache(ratchet_state_t *state, const unsigned char *chain_key, uint32_t index, uint32_t ratchet_index);
void add_root_key_to_cache(ratchet_state_t *state, const unsigned char *root_key, uint32_t ratchet_index);

#endif // CACHE_H