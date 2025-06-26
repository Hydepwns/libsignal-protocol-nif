#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>
#include <openssl/evp.h>

// Forward declarations
typedef struct message_key message_key_t;
typedef struct ratchet_chain ratchet_chain_t;
typedef struct cache_stats cache_stats_t;
typedef struct chain_key_cache chain_key_cache_t;
typedef struct root_key_cache root_key_cache_t;
typedef struct ratchet_state ratchet_state_t;
typedef struct simple_session simple_session_t;

// Message key structure
struct message_key
{
  unsigned char key[32]; // MESSAGE_KEY_LEN
  uint32_t index;
  uint32_t ratchet_index;
};

// Ratchet chain structure
struct ratchet_chain
{
  EVP_PKEY *dh_key;
  unsigned char chain_key[32]; // CHAIN_KEY_LEN
  uint32_t chain_index;
  message_key_t message_keys[2000]; // MAX_MESSAGE_KEYS
  size_t message_key_count;
  message_key_t skip_keys[100]; // MAX_SKIP_KEYS
  size_t skip_key_count;
};

// Cache statistics structure
struct cache_stats
{
  size_t hits;
  size_t misses;
  size_t current_size;
  size_t max_size;
  double hit_ratio;
  size_t last_adjustment;
};

// Chain key cache structure
struct chain_key_cache
{
  unsigned char chain_key[32]; // CHAIN_KEY_LEN
  uint32_t index;
  uint32_t ratchet_index;
};

// Root key cache structure
struct root_key_cache
{
  unsigned char root_key[32]; // ROOT_KEY_LEN
  uint32_t ratchet_index;
};

// Ratchet state structure
struct ratchet_state
{
  ratchet_chain_t sending_chain;
  ratchet_chain_t receiving_chain;
  unsigned char root_key[32]; // ROOT_KEY_LEN
  uint32_t sending_ratchet_index;
  uint32_t receiving_ratchet_index;
  chain_key_cache_t *chain_key_cache;
  size_t chain_key_cache_size;
  size_t chain_key_cache_count;
  root_key_cache_t *root_key_cache;
  size_t root_key_cache_size;
  size_t root_key_cache_count;
  cache_stats_t chain_key_stats;
  cache_stats_t root_key_stats;
};

// Simple session structure without pointers for serialization
struct simple_session
{
  unsigned char root_key[32];          // ROOT_KEY_LEN
  unsigned char sending_chain_key[32]; // CHAIN_KEY_LEN
  uint32_t sending_chain_index;
  uint32_t sending_ratchet_index;
  uint32_t receiving_ratchet_index;
  // Store the ephemeral key as raw bytes instead of pointer
  unsigned char ephemeral_key[32]; // CURVE25519_KEY_SIZE
};

#endif // TYPES_H