#include "performance.h"
#include <erl_nif.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

// Cache configuration
#define MAX_CACHE_SIZE 1000
#define CACHE_CLEANUP_INTERVAL 300           // 5 minutes
#define MEMORY_THRESHOLD (100 * 1024 * 1024) // 100MB

// Cache entry structure
typedef struct
{
  ErlNifBinary key;
  ErlNifBinary value;
  time_t timestamp;
  size_t access_count;
} cache_entry_t;

// Memory pool entry
typedef struct
{
  void *ptr;
  size_t size;
  time_t allocated;
  int in_use;
} memory_pool_entry_t;

// Performance monitoring structure
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

// Global variables
static cache_entry_t *g_cache = NULL;
static memory_pool_entry_t *g_memory_pool = NULL;
static performance_stats_t g_stats = {0};
static pthread_mutex_t g_cache_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_memory_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_stats_mutex = PTHREAD_MUTEX_INITIALIZER;

// Forward declarations
static void cleanup_cache(void);
static void cleanup_memory_pool(void);
static cache_entry_t *find_cache_entry(const ErlNifBinary *key);
static void add_cache_entry(const ErlNifBinary *key, const ErlNifBinary *value);
static void *allocate_from_pool(size_t size);
static void return_to_pool(void *ptr);

// Initialize performance monitoring
int performance_init(void)
{
  pthread_mutex_lock(&g_stats_mutex);

  g_stats.start_time = time(NULL);
  g_stats.last_cleanup = g_stats.start_time;
  g_stats.max_cache_size = MAX_CACHE_SIZE;
  g_stats.max_connections = 100;

  // Allocate cache
  g_cache = enif_alloc(MAX_CACHE_SIZE * sizeof(cache_entry_t));
  if (!g_cache)
  {
    pthread_mutex_unlock(&g_stats_mutex);
    return 0;
  }
  memset(g_cache, 0, MAX_CACHE_SIZE * sizeof(cache_entry_t));

  // Allocate memory pool
  g_memory_pool = enif_alloc(100 * sizeof(memory_pool_entry_t));
  if (!g_memory_pool)
  {
    enif_free(g_cache);
    g_cache = NULL;
    pthread_mutex_unlock(&g_stats_mutex);
    return 0;
  }
  memset(g_memory_pool, 0, 100 * sizeof(memory_pool_entry_t));

  pthread_mutex_unlock(&g_stats_mutex);
  return 1;
}

// Cleanup performance monitoring
void performance_cleanup(void)
{
  pthread_mutex_lock(&g_cache_mutex);
  pthread_mutex_lock(&g_memory_mutex);
  pthread_mutex_lock(&g_stats_mutex);

  // Cleanup cache
  if (g_cache)
  {
    for (size_t i = 0; i < g_stats.cache_size; i++)
    {
      if (g_cache[i].key.data)
      {
        enif_release_binary(&g_cache[i].key);
      }
      if (g_cache[i].value.data)
      {
        enif_release_binary(&g_cache[i].value);
      }
    }
    enif_free(g_cache);
    g_cache = NULL;
  }

  // Cleanup memory pool
  if (g_memory_pool)
  {
    for (size_t i = 0; i < g_stats.pool_size; i++)
    {
      if (g_memory_pool[i].ptr && !g_memory_pool[i].in_use)
      {
        enif_free(g_memory_pool[i].ptr);
      }
    }
    enif_free(g_memory_pool);
    g_memory_pool = NULL;
  }

  pthread_mutex_unlock(&g_stats_mutex);
  pthread_mutex_unlock(&g_memory_mutex);
  pthread_mutex_unlock(&g_cache_mutex);
}

// Get cached value
int performance_get_cache(const ErlNifBinary *key, ErlNifBinary *value)
{
  pthread_mutex_lock(&g_cache_mutex);

  // Check if cleanup is needed
  time_t now = time(NULL);
  if (now - g_stats.last_cleanup > CACHE_CLEANUP_INTERVAL)
  {
    cleanup_cache();
    g_stats.last_cleanup = now;
  }

  cache_entry_t *entry = find_cache_entry(key);
  if (entry)
  {
    // Cache hit
    *value = entry->value;
    entry->access_count++;
    entry->timestamp = now;

    pthread_mutex_lock(&g_stats_mutex);
    g_stats.cache_hits++;
    pthread_mutex_unlock(&g_stats_mutex);

    pthread_mutex_unlock(&g_cache_mutex);
    return 1;
  }

  // Cache miss
  pthread_mutex_lock(&g_stats_mutex);
  g_stats.cache_misses++;
  pthread_mutex_unlock(&g_stats_mutex);

  pthread_mutex_unlock(&g_cache_mutex);
  return 0;
}

// Set cache value
void performance_set_cache(const ErlNifBinary *key, const ErlNifBinary *value)
{
  pthread_mutex_lock(&g_cache_mutex);

  // Check if we need to evict entries
  if (g_stats.cache_size >= g_stats.max_cache_size)
  {
    cleanup_cache();
  }

  add_cache_entry(key, value);

  pthread_mutex_unlock(&g_cache_mutex);
}

// Allocate memory with monitoring
void *performance_alloc(size_t size)
{
  pthread_mutex_lock(&g_memory_mutex);

  // Try to get from pool first
  void *ptr = allocate_from_pool(size);
  if (ptr)
  {
    pthread_mutex_unlock(&g_memory_mutex);
    return ptr;
  }

  // Allocate new memory
  ptr = enif_alloc(size);
  if (ptr)
  {
    pthread_mutex_lock(&g_stats_mutex);
    g_stats.total_allocated += size;
    g_stats.current_memory += size;
    if (g_stats.current_memory > g_stats.peak_memory)
    {
      g_stats.peak_memory = g_stats.current_memory;
    }
    pthread_mutex_unlock(&g_stats_mutex);
  }

  pthread_mutex_unlock(&g_memory_mutex);
  return ptr;
}

// Free memory with monitoring
void performance_free(void *ptr, size_t size)
{
  pthread_mutex_lock(&g_memory_mutex);

  // Try to return to pool
  if (size <= 4096)
  { // Only pool small allocations
    return_to_pool(ptr);
  }
  else
  {
    enif_free(ptr);
  }

  pthread_mutex_lock(&g_stats_mutex);
  g_stats.total_freed += size;
  g_stats.current_memory -= size;
  pthread_mutex_unlock(&g_stats_mutex);

  pthread_mutex_unlock(&g_memory_mutex);
}

// Record operation timing
void performance_record_operation(operation_type_t type, double duration)
{
  pthread_mutex_lock(&g_stats_mutex);

  g_stats.total_operations++;

  switch (type)
  {
  case OP_ENCRYPT:
    g_stats.avg_encryption_time =
        (g_stats.avg_encryption_time * (g_stats.total_operations - 1) + duration) / g_stats.total_operations;
    break;
  case OP_DECRYPT:
    g_stats.avg_decryption_time =
        (g_stats.avg_decryption_time * (g_stats.total_operations - 1) + duration) / g_stats.total_operations;
    break;
  }

  pthread_mutex_unlock(&g_stats_mutex);
}

// Get performance statistics
void performance_get_stats(performance_stats_t *stats)
{
  pthread_mutex_lock(&g_stats_mutex);
  *stats = g_stats;
  pthread_mutex_unlock(&g_stats_mutex);
}

// Connection pool management
void *performance_get_connection(void)
{
  pthread_mutex_lock(&g_memory_mutex);

  // Find available connection
  for (size_t i = 0; i < g_stats.pool_size; i++)
  {
    if (!g_memory_pool[i].in_use)
    {
      g_memory_pool[i].in_use = 1;
      g_stats.active_connections++;
      pthread_mutex_unlock(&g_memory_mutex);
      return g_memory_pool[i].ptr;
    }
  }

  // Create new connection if pool not full
  if (g_stats.pool_size < g_stats.max_connections)
  {
    void *conn = enif_alloc(sizeof(connection_t));
    if (conn)
    {
      g_memory_pool[g_stats.pool_size].ptr = conn;
      g_memory_pool[g_stats.pool_size].in_use = 1;
      g_memory_pool[g_stats.pool_size].allocated = time(NULL);
      g_stats.pool_size++;
      g_stats.active_connections++;
    }
    pthread_mutex_unlock(&g_memory_mutex);
    return conn;
  }

  pthread_mutex_unlock(&g_memory_mutex);
  return NULL;
}

void performance_return_connection(void *conn)
{
  pthread_mutex_lock(&g_memory_mutex);

  for (size_t i = 0; i < g_stats.pool_size; i++)
  {
    if (g_memory_pool[i].ptr == conn)
    {
      g_memory_pool[i].in_use = 0;
      g_stats.active_connections--;
      break;
    }
  }

  pthread_mutex_unlock(&g_memory_mutex);
}

// Private functions
static void cleanup_cache(void)
{
  time_t now = time(NULL);
  size_t new_size = 0;

  for (size_t i = 0; i < g_stats.cache_size; i++)
  {
    // Remove entries older than 1 hour or with low access count
    if (now - g_cache[i].timestamp < 3600 && g_cache[i].access_count > 1)
    {
      if (new_size != i)
      {
        g_cache[new_size] = g_cache[i];
      }
      new_size++;
    }
    else
    {
      // Free memory
      if (g_cache[i].key.data)
      {
        enif_release_binary(&g_cache[i].key);
      }
      if (g_cache[i].value.data)
      {
        enif_release_binary(&g_cache[i].value);
      }
    }
  }

  g_stats.cache_size = new_size;
}

static void cleanup_memory_pool(void)
{
  time_t now = time(NULL);

  for (size_t i = 0; i < g_stats.pool_size; i++)
  {
    if (!g_memory_pool[i].in_use &&
        now - g_memory_pool[i].allocated > 300)
    { // 5 minutes
      enif_free(g_memory_pool[i].ptr);
      g_memory_pool[i].ptr = NULL;
    }
  }
}

static cache_entry_t *find_cache_entry(const ErlNifBinary *key)
{
  for (size_t i = 0; i < g_stats.cache_size; i++)
  {
    if (g_cache[i].key.size == key->size &&
        memcmp(g_cache[i].key.data, key->data, key->size) == 0)
    {
      return &g_cache[i];
    }
  }
  return NULL;
}

static void add_cache_entry(const ErlNifBinary *key, const ErlNifBinary *value)
{
  if (g_stats.cache_size >= g_stats.max_cache_size)
  {
    return;
  }

  cache_entry_t *entry = &g_cache[g_stats.cache_size];

  // Copy key
  enif_alloc_binary(key->size, &entry->key);
  memcpy(entry->key.data, key->data, key->size);

  // Copy value
  enif_alloc_binary(value->size, &entry->value);
  memcpy(entry->value.data, value->data, value->size);

  entry->timestamp = time(NULL);
  entry->access_count = 1;

  g_stats.cache_size++;
}

static void *allocate_from_pool(size_t size)
{
  for (size_t i = 0; i < g_stats.pool_size; i++)
  {
    if (!g_memory_pool[i].in_use && g_memory_pool[i].size >= size)
    {
      g_memory_pool[i].in_use = 1;
      return g_memory_pool[i].ptr;
    }
  }
  return NULL;
}

static void return_to_pool(void *ptr)
{
  for (size_t i = 0; i < g_stats.pool_size; i++)
  {
    if (g_memory_pool[i].ptr == ptr)
    {
      g_memory_pool[i].in_use = 0;
      return;
    }
  }

  // Add to pool if there's space
  if (g_stats.pool_size < 100)
  {
    g_memory_pool[g_stats.pool_size].ptr = ptr;
    g_memory_pool[g_stats.pool_size].in_use = 0;
    g_memory_pool[g_stats.pool_size].allocated = time(NULL);
    g_stats.pool_size++;
  }
  else
  {
    // Pool is full, free the memory
    enif_free(ptr);
  }
}
