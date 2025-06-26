#ifndef CONSTANTS_H
#define CONSTANTS_H

// Signal Protocol constants
#define MESSAGE_KEY_LEN 32
#define CHAIN_KEY_LEN 32
#define ROOT_KEY_LEN 32
#define MAX_MESSAGE_KEYS 2000
#define MAX_SKIP_KEYS 100
#define RATCHET_ROTATION_THRESHOLD 100

// Cache constants
#define CHAIN_KEY_CACHE_SIZE 10
#define ROOT_KEY_CACHE_SIZE 5
#define MIN_CHAIN_KEY_CACHE_SIZE 5
#define MAX_CHAIN_KEY_CACHE_SIZE 20
#define MIN_ROOT_KEY_CACHE_SIZE 3
#define MAX_ROOT_KEY_CACHE_SIZE 10
#define CACHE_GROWTH_FACTOR 1.5
#define CACHE_SHRINK_FACTOR 0.75
#define CACHE_HIT_THRESHOLD 0.7
#define CACHE_MISS_THRESHOLD 0.3

// Key validation constants
#define MIN_KEY_SIZE 32      // Minimum key size in bytes (Curve25519)
#define MAX_KEY_SIZE 32      // Maximum key size in bytes (Curve25519)
#define CURVE_NID NID_X25519 // Curve25519 curve

// Scrypt parameters
#define SCRYPT_N 32768
#define SCRYPT_R 8
#define SCRYPT_P 1

// Header size: 8 bytes for indices, 32 for Curve25519 public key
#define HEADER_SIZE (8 + 32)

#endif // CONSTANTS_H