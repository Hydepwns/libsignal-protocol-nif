#include "cache.h"
#include "../constants.h"
#include "../types.h"
#include "../utils/utils.h"
#include <stdlib.h>
#include <string.h>

// Cache operations
void update_cache_stats(cache_stats_t *stats, int hit)
{
  if (!stats)
    return;

  if (hit)
  {
    stats->hits++;
  }
  else
  {
    stats->misses++;
  }

  size_t total = stats->hits + stats->misses;
  if (total > 0)
  {
    stats->hit_ratio = (double)stats->hits / total;
  }

  stats->current_size = stats->current_size; // Keep current size
}

void adjust_cache_size(cache_stats_t *stats, size_t *cache_size)
{
  if (!stats || !cache_size)
    return;

  // Only adjust every 100 operations to avoid thrashing
  size_t total_ops = stats->hits + stats->misses;
  if (total_ops - stats->last_adjustment < 100)
  {
    return;
  }

  if (stats->hit_ratio > CACHE_HIT_THRESHOLD && *cache_size < stats->max_size)
  {
    // Increase cache size
    size_t new_size = (size_t)(*cache_size * CACHE_GROWTH_FACTOR);
    if (new_size > stats->max_size)
    {
      new_size = stats->max_size;
    }
    *cache_size = new_size;
  }
  else if (stats->hit_ratio < CACHE_MISS_THRESHOLD && *cache_size > stats->max_size / 2)
  {
    // Decrease cache size
    size_t new_size = (size_t)(*cache_size * CACHE_SHRINK_FACTOR);
    if (new_size < stats->max_size / 2)
    {
      new_size = stats->max_size / 2;
    }
    *cache_size = new_size;
  }

  stats->last_adjustment = total_ops;
}

int get_cached_chain_key(ratchet_state_t *state, uint32_t index, uint32_t ratchet_index, unsigned char *chain_key)
{
  if (!state || !chain_key)
    return 0;

  for (size_t i = 0; i < state->chain_key_cache_count; i++)
  {
    if (state->chain_key_cache[i].index == index &&
        state->chain_key_cache[i].ratchet_index == ratchet_index)
    {
      memcpy(chain_key, state->chain_key_cache[i].chain_key, CHAIN_KEY_LEN);
      update_cache_stats(&state->chain_key_stats, 1); // Hit
      return 1;
    }
  }

  update_cache_stats(&state->chain_key_stats, 0); // Miss
  return 0;
}

void add_chain_key_to_cache(ratchet_state_t *state, const unsigned char *chain_key, uint32_t index, uint32_t ratchet_index)
{
  if (!state || !chain_key)
    return;

  // Check if we need to resize the cache
  if (state->chain_key_cache_count >= state->chain_key_cache_size)
  {
    size_t new_size = state->chain_key_cache_size * 2;
    if (new_size > MAX_CHAIN_KEY_CACHE_SIZE)
    {
      new_size = MAX_CHAIN_KEY_CACHE_SIZE;
    }

    chain_key_cache_t *new_cache = realloc(state->chain_key_cache, new_size * sizeof(chain_key_cache_t));
    if (!new_cache)
      return; // Failed to allocate

    state->chain_key_cache = new_cache;
    state->chain_key_cache_size = new_size;
  }

  // Add the new entry
  memcpy(state->chain_key_cache[state->chain_key_cache_count].chain_key, chain_key, CHAIN_KEY_LEN);
  state->chain_key_cache[state->chain_key_cache_count].index = index;
  state->chain_key_cache[state->chain_key_cache_count].ratchet_index = ratchet_index;
  state->chain_key_cache_count++;

  // Adjust cache size based on performance
  adjust_cache_size(&state->chain_key_stats, &state->chain_key_cache_size);
}

void add_root_key_to_cache(ratchet_state_t *state, const unsigned char *root_key, uint32_t ratchet_index)
{
  if (!state || !root_key)
    return;

  // Check if we need to resize the cache
  if (state->root_key_cache_count >= state->root_key_cache_size)
  {
    size_t new_size = state->root_key_cache_size * 2;
    if (new_size > MAX_ROOT_KEY_CACHE_SIZE)
    {
      new_size = MAX_ROOT_KEY_CACHE_SIZE;
    }

    root_key_cache_t *new_cache = realloc(state->root_key_cache, new_size * sizeof(root_key_cache_t));
    if (!new_cache)
      return; // Failed to allocate

    state->root_key_cache = new_cache;
    state->root_key_cache_size = new_size;
  }

  // Add the new entry
  memcpy(state->root_key_cache[state->root_key_cache_count].root_key, root_key, ROOT_KEY_LEN);
  state->root_key_cache[state->root_key_cache_count].ratchet_index = ratchet_index;
  state->root_key_cache_count++;

  // Adjust cache size based on performance
  adjust_cache_size(&state->root_key_stats, &state->root_key_cache_size);
}

// NIF function implementations
ERL_NIF_TERM get_cache_stats(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  if (argc != 1)
  {
    return enif_make_badarg(env);
  }

  ErlNifBinary session;
  if (!enif_inspect_binary(env, argv[0], &session))
  {
    return make_error(env, "Invalid session binary");
  }

  // For now, return dummy cache stats
  // In a real implementation, this would extract stats from the session state
  ERL_NIF_TERM chain_key_stats = enif_make_tuple6(env,
                                                  enif_make_ulong(env, 0),                    // hits
                                                  enif_make_ulong(env, 0),                    // misses
                                                  enif_make_ulong(env, 0),                    // current_size
                                                  enif_make_ulong(env, CHAIN_KEY_CACHE_SIZE), // max_size
                                                  enif_make_double(env, 0.0),                 // hit_ratio
                                                  enif_make_ulong(env, 0)                     // last_adjustment
  );

  ERL_NIF_TERM root_key_stats = enif_make_tuple6(env,
                                                 enif_make_ulong(env, 0),                   // hits
                                                 enif_make_ulong(env, 0),                   // misses
                                                 enif_make_ulong(env, 0),                   // current_size
                                                 enif_make_ulong(env, ROOT_KEY_CACHE_SIZE), // max_size
                                                 enif_make_double(env, 0.0),                // hit_ratio
                                                 enif_make_ulong(env, 0)                    // last_adjustment
  );

  ERL_NIF_TERM stats = enif_make_tuple2(env, chain_key_stats, root_key_stats);
  return make_ok(env, stats);
}

ERL_NIF_TERM reset_cache_stats(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  if (argc != 1)
  {
    return enif_make_badarg(env);
  }

  ErlNifBinary session;
  if (!enif_inspect_binary(env, argv[0], &session))
  {
    return make_error(env, "Invalid session binary");
  }

  // For now, just return success
  // In a real implementation, this would reset the cache stats in the session state
  return make_ok(env, enif_make_atom(env, "ok"));
}

ERL_NIF_TERM set_cache_size(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  if (argc != 3)
  {
    return enif_make_badarg(env);
  }

  ErlNifBinary session;
  unsigned long chain_key_size, root_key_size;

  if (!enif_inspect_binary(env, argv[0], &session) ||
      !enif_get_ulong(env, argv[1], &chain_key_size) ||
      !enif_get_ulong(env, argv[2], &root_key_size))
  {
    return make_error(env, "Invalid arguments");
  }

  // Validate cache sizes
  if (chain_key_size < MIN_CHAIN_KEY_CACHE_SIZE || chain_key_size > MAX_CHAIN_KEY_CACHE_SIZE)
  {
    return make_error(env, "Invalid chain key cache size");
  }

  if (root_key_size < MIN_ROOT_KEY_CACHE_SIZE || root_key_size > MAX_ROOT_KEY_CACHE_SIZE)
  {
    return make_error(env, "Invalid root key cache size");
  }

  // For now, just return success
  // In a real implementation, this would update the cache sizes in the session state
  return make_ok(env, enif_make_atom(env, "ok"));
}