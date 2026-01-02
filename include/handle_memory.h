#ifndef HANDLE_MEMORY_H
#define HANDLE_MEMORY_H

#include <stddef.h>
#include <stdbool.h>
#if MEM_THREAD_SAFE
#include <pthread.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if MEM_THREAD_SAFE
#define MEM_LOCK(pool) pthread_mutex_lock(&(pool)->lock)
#define MEM_UNLOCK(pool) pthread_mutex_unlock(&(pool)->lock)
#else
#define MEM_LOCK(pool) (void)0
#define MEM_UNLOCK(pool) (void)0
#endif

/* @brief Memory block container tracking ownership and references. */
typedef struct MemoryContainer MemoryContainer;

/* @brief Smart pointer wrapper managing container references. */
typedef struct MemoryPointer MemoryPointer;

/* @brief Central registry managing all allocated memory containers. */
typedef struct MemoryPool MemoryPool;

/**
 * @brief Arena allocator for high-performance bulk allocations
 *
 * Arena allocators provide O(1) allocation/deallocation with excellent
 * cache locality.
 * 
 * All allocations from an arena are freed simultaneously
 * when the arena is destroyed.
 *
 * @struct MemoryArena
 */
typedef struct MemoryArena MemoryArena;

struct MemoryContainer {
    size_t address;
    size_t size;
    int ref_count;
    void* data;
};

struct MemoryPointer {
    char* variable_name;
    MemoryContainer* container;
};

struct MemoryPool {
    MemoryContainer** containers;
    size_t capacity;
    size_t count;
    MemoryPool* next;
#if MEM_THREAD_SAFE
    pthread_mutex_t lock;
#endif
};

/** 
  * @brief Initializes a memory pool with specified initial capacity. 
  * @param pool Pointer to uninitialized MemoryPool structure
  * @param initial_capacity Initial number of containers to allocate space
  * @return true on successful initialization
  * @return false on allocation failure or invalid parameters
  */
bool mem_pool_init(MemoryPool* pool, size_t initial_capacity);

/**
 * @brief Creates a new MemoryPointer without allocating backing memory.
 * @param var_name Human-readable identifier for debugging/tracking
 * @param size_hint Expected allocation size (0 if unknown)
 * @return Pointer to new MemoryPointer, or NULL on failure
*/
MemoryPointer* mem_pointer_create(const char* var_name, size_t size);


MemoryContainer* mem_container_create(size_t address, size_t size);

/**
 * @brief Adds an existing container to a memory pool.
 * @param pool Initialized MemoryPool
 * @param container Valid MemoryContainer not already in a pool
 * @return true on successful addition
 * @return false on failure or duplicate container
*/
bool mem_pool_add_container(MemoryPool* pool, MemoryContainer* container);

/**
 * @brief Removes a container from pool and optionally destroys it.
 *
 * @param pool MemoryPool from which to remove container
 * @param container Container to remove (must be in pool)
 * @param destroy_if_last_ref If true, destroys container when ref_count <= 0
 * @return true if container was found and removed
 * @return false if container not found or parameters invalid
 */
bool remove_container_from_pool(MemoryPool* pool, MemoryContainer* container, bool destroy_if_last_ref);

/**
 * @brief Grows the pool capacity when full.
 * @param pool MemoryPool to grow
 * @return true on success, false on OOM
 */
bool grow_pool_capacity(MemoryPool* pool);

/**
 * @brief Allocates or reallocates memory for a MemoryPointer.
 * @param ptr Valid MemoryPointer (must be created with mem_pointer_create)
 * @param size Memory size to allocate in bytes (>0)
 * @param pool Initialized MemoryPool for container tracking
 * @return true on successful allocation
 * @return false on failure (pointer remains valid but unallocated)
*/
bool mem_pointer_allocate(MemoryPointer* ptr, size_t size, MemoryPool* pool);

/**
 * @brief Destroys a MemoryPointer and potentially its backing memory.
 * @param ptr MemoryPointer to destroy (may be NULL)
 * @param pool Pool containing pointer's container
*/
void mem_pointer_destroy(MemoryPointer* ptr, MemoryPool* pool);

/**
 * @brief Destroys a MemoryContainer and its allocated memory.
 * @param container MemoryContainer to destroy (may be NULL)
*/
void mem_container_destroy(MemoryContainer* container);

/** 
  * @brief Completely destroys a memory pool and all contained allocations. 
  * @param pool Pointer to initialized MemoryPool (may be NULL)
  */
void mem_pool_destroy(MemoryPool* pool);

/**
 * @brief Computes a deterministic hash for string identifiers.
 * 
 * Uses FNV-1a hash algorithm for good distribution properties.
 * 
 * Suitable for use as container address identifiers.
 * @param str Null-terminated string to hash
 * @return 64-bit FNV-1a hash value
*/
size_t mem_compute_hash(const char* str);

/**
 * @brief Gets the current number of containers in a pool.
 * @param pool Initialized MemoryPool
 * @return Number of containers currently in the pool
*/
size_t mem_pool_get_count(const MemoryPool* pool);

/**
 * @brief Gets the total allocated memory in a pool.
 * @param pool Initialized MemoryPool
 * @return Total bytes allocated across all containers in the pool
*/
size_t mem_pool_get_total_bytes(const MemoryPool* pool);

/**
 * @brief Creates a new memory arena.
 * @param arena_size Total size of the arena in bytes
 * @return Pointer to new MemoryArena, or NULL on failure
*/
MemoryArena* mem_arena_create(size_t arena_size);

/**
 * @brief Allocates memory from an arena.
 * @param arena Valid MemoryArena
 * @param size Size to allocate in bytes
 * @return Pointer to allocated memory, or NULL if arena is full
*/
void* mem_arena_alloc(MemoryArena* arena, size_t size);

/**
 * @brief Destroys a memory arena and all its allocations.
 * @param arena MemoryArena to destroy (may be NULL)
*/
void mem_arena_destroy(MemoryArena* arena);

#ifdef DEBUG_MEMORY_MANAGER

/**
 * @brief Validates the integrity of a memory pool.
 *
 * Performs sanity checks on pool structure and all containers.
 * 
 * Only available when DEBUG_MEMORY_MANAGER is defined.
 *
 * @param pool MemoryPool to validate
 *
 * @return true if pool is valid
 * @return false if corruption or inconsistency detected
*/
bool mem_pool_validate(const MemoryPool* pool);

/**
 * @brief Dumps pool information to stderr.
 * Prints detailed information about all containers in the pool.
 * 
 * Only available when DEBUG_MEMORY is defined.
 *
 * @param pool MemoryPool to dump
 * @param detailed If true, print per-container details
*/
void mem_pool_dump(const MemoryPool* pool, bool detailed);
#endif

/**
 * @brief Sets a custom memory allocation failure handler.
 * @param handler Function to call when memory allocation fails.
*/
void mem_set_oom_handler(void (*handler)(size_t requested));

/**
 * @brief Default initial pool capacity.
 *
 * Can be overridden at compile time.
*/
#ifndef MEM_POOL_DEFAULT_CAPACITY
#define MEM_POOL_DEFAULT_CAPACITY 16
#endif

/**
 * @brief Memory alignment for allocations.
 *
 * Defaults to 8-byte alignment. 
 * 
 * Can be increased for SIMD operations.
 */
#ifndef MEM_ALIGNMENT
#define MEM_ALIGNMENT 8
#endif

/**
 * @brief Enable thread-safe operations
 * Define to 1 to enable mutex locking on pool operations.
 * 
 * Requires linking with pthreads or similar threading library.
*/
#ifndef MEM_THREAD_SAFE
#define MEM_THREAD_SAFE 0
#endif

#ifndef SHRINK_POOL_THRESHOLD
#define SHRINK_POOL_THRESHOLD 4
#endif

#ifndef MIN_POOL_CAPACITY
#define MIN_POOL_CAPACITY 16
#endif

#ifndef REF_DEC
#if MEM_THREAD_SAFE
#define REF_DEC(container) __atomic_sub_fetch(&(container)->ref_count, 1, __ATOMIC_SEQ_CST)
#define REF_INC(container) __atomic_add_fetch(&(container)->ref_count, 1, __ATOMIC_SEQ_CST)
#else
#define REF_DEC(container) ((container)->ref_count--)
#define REF_INC(container) ((container)->ref_count++)
#endif
#endif

#ifndef REF_GET
#if MEM_THREAD_SAFE
#define REF_GET(container) __atomic_load_n(&(container)->ref_count, __ATOMIC_RELAXED)
#else
#define REF_GET(container) ((container)->ref_count)
#endif
#endif

#ifdef __cplusplus
}
#endif

#endif