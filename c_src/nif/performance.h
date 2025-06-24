#ifndef PERFORMANCE_H
#define PERFORMANCE_H

#include <erl_nif.h>
#include <stddef.h>
#include <time.h>

// Operation types for performance tracking
typedef enum
{
  OP_ENCRYPT,
  OP_DECRYPT,
  OP_KEY_GENERATION,
  OP_SIGNATURE,
  OP_VERIFICATION
} operation_type_t;

// Connection structure for connection pooling
typedef struct
{
  void *context;
  time_t created;
  int active;
} connection_t;

// Performance statistics structure
typedef struct
{
  // Cache statistics
  size_t cache_hits;
  size_t cache_misses;
  size_t cache_size;
  size_t max_cache_size;

  // Memory statistics
  size_t total_allocated;
  size_t total_freed;
  size_t peak_memory;
  size_t current_memory;

  // Performance metrics
  double avg_encryption_time;
  double avg_decryption_time;
  size_t total_operations;

  // Connection pool
  size_t pool_size;
  size_t active_connections;
  size_t max_connections;

  // Timestamps
  time_t last_cleanup;
  time_t start_time;
} performance_stats_t;

// Performance monitoring functions
int performance_init(void);
void performance_cleanup(void);

// Cache functions
int performance_get_cache(const ErlNifBinary *key, ErlNifBinary *value);
void performance_set_cache(const ErlNifBinary *key, const ErlNifBinary *value);

// Memory management functions
void *performance_alloc(size_t size);
void performance_free(void *ptr, size_t size);

// Performance tracking functions
void performance_record_operation(operation_type_t type, double duration);
void performance_get_stats(performance_stats_t *stats);

// Connection pool functions
void *performance_get_connection(void);
void performance_return_connection(void *conn);

// Utility functions
double performance_get_time(void);
void performance_log_stats(const char *prefix);

#endif // PERFORMANCE_H