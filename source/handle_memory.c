#include "handle_memory.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#if MEM_THREAD_SAFE
#include <pthread.h>
#endif

#ifdef DEBUG_MEMORY_MANAGER
#define DEBUG_LOG(fmt, ...) fprintf(stderr, "[MEM] " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_LOG(...) (void)0
#endif

static bool grow_pool_capacity(MemoryPool* pool);
static size_t align_size(size_t size);
static void zero_memory(void* ptr, size_t size);

/* Default out-of-memory handler function. */
static void default_oom_handler(size_t requested) {
    fprintf(stderr, "Memory allocation failed: requested %zu bytes\n", requested);
}

static void (*g_oom_handler)(size_t) = default_oom_handler;

/* Arena allocator structure implementation */
struct MemoryArena {
    void* memory;
    size_t size;
    size_t used;
    MemoryArena* next;
    unsigned char alignment_padding[7];
};


bool mem_pool_init(MemoryPool* pool, size_t initial_capacity) {
    /* validate parameters */
    if (!pool) {
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("mem_pool_init: NULL pool pointer.");
#endif
        errno = EINVAL;
        return false;
    }

    /* initialize structure to safe defaults */
    pool->containers = NULL;
    pool->capacity = 0;
    pool->count = 0;
    pool->next = NULL;

#if MEM_THREAD_SAFE
    /* initialize mutex, before any allocations */
    int mutex_result = pthread_mutex_init(&pool->lock, NULL);
    if (mutex_result != 0) {
        switch (mutex_result) {
        case EAGAIN: errno = EAGAIN; break;
        case ENOMEM: errno = ENOMEM; break;
        case EPERM:  errno = EPERM;  break;
        default:     errno = EINVAL; break;
        }
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("mem_pool_init: mutex init failed with error %d.", mutex_result);
#endif
        return false;
    }
#endif

    /* determine capacity */
    if (initial_capacity == 0)
        initial_capacity = MEM_POOL_DEFAULT_CAPACITY;

    /* check for potential overflow in size calculation */
    if (initial_capacity > SIZE_MAX / sizeof(MemoryContainer*)) {
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("mem_pool_init: capacity %zu would overflow.", initial_capacity);
#endif
        goto error_cleanup;
    }

    size_t allocation_size = initial_capacity * sizeof(MemoryContainer*);

    /* allocate container array with zero initialization */
    pool->containers = calloc(initial_capacity, sizeof(MemoryContainer*));

    if (!pool->containers) {
        g_oom_handler(allocation_size);
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("mem_pool_init: calloc failed for %zu bytes.", allocation_size);
#endif
        goto error_cleanup;
    }

    /* set pool properties */
    pool->capacity = initial_capacity;
    pool->count = 0;
    pool->next = NULL;

#ifdef DEBUG_MEMORY_MANAGER
    DEBUG_LOG("Pool initialized: capacity=%zu, allocation=%zu bytes.",
        initial_capacity, allocation_size);
#endif

    return true;

error_cleanup:
    /* clean up in reverse order of initialization */
    if (pool->containers) {
        free(pool->containers);
        pool->containers = NULL;
    }

#if MEM_THREAD_SAFE
    /* only destroy mutex if it was successfully initialized */
    pthread_mutex_destroy(&pool->lock);
#endif

    /* ensure structure is in a consistent state */
    pool->capacity = 0;
    pool->count = 0;
    pool->next = NULL;

    errno = ENOMEM;
    return false;
}

void mem_pool_destroy(MemoryPool* pool) {
    /* early return for NULL input */
    if (!pool) return;
    MemoryPool* current = pool;

    while (current) {
        /* store next pointer before modifying current */
        MemoryPool* next_pool = current->next;

        /* lock the current pool for thread-safe destruction */
        MEM_LOCK(current);

#ifdef DEBUG_MEMORY_MANAGER
        /* debug logging for non-NULL containers */
        if (current->count > 0 && current->containers) {
            size_t live_containers = 0;
            for (size_t i = 0; i < current->count; i++) {
                if (current->containers[i] && current->containers[i]->ref_count > 0)
                    live_containers++;
            }
            if (live_containers > 0) {
                DEBUG_LOG("Warning: %zu container(s) still referenced during pool destruction.",
                    live_containers);
            }
        }
#endif

        /* destroy all containers in the pool */
        if (current->containers) {
            for (size_t i = current->count; i-- > 0; ) {
                MemoryContainer* container = current->containers[i];
                if (container) {
                    /* check if container is still referenced */
                    if (REF_GET(container) > 0) {
#ifdef DEBUG_MEMORY_MANAGER
                        DEBUG_LOG("Warning: Container %p still has %d references during destruction.",
                            (void*)container->address, container->ref_count);
#endif
                        /* force destroy despite references */
                        container->ref_count = 0;
                    }
                    mem_container_destroy(container);
                }
            }

            /* calculate actual memory used for zeroing */
            size_t allocated_bytes = current->capacity * sizeof(MemoryContainer*);

            /* clear sensitive data from containers array */
            zero_memory(current->containers, allocated_bytes);

            /* free the containers array */
            free(current->containers);
            current->containers = NULL;
        }

        /* clear pool metadata while still holding lock */
        current->capacity = 0;
        current->count = 0;
        current->next = NULL;

        /* unlock before destroying mutex */
        MEM_UNLOCK(current);

#if MEM_THREAD_SAFE
        /* destroy mutex, unlocked before destruction */
        int mutex_result = pthread_mutex_destroy(&current->lock);
        if (mutex_result != 0 && mutex_result != EBUSY) {
#ifdef DEBUG_MEMORY_MANAGER
            DEBUG_LOG("Warning: pthread_mutex_destroy failed with error %d.", mutex_result);
#endif
        }
#endif

        /* clear the entire pool structure for security */
        zero_memory(current, sizeof(MemoryPool));

        /* move to next pool in chain */
        current = next_pool;
    }

#ifdef DEBUG_MEMORY_MANAGER
    DEBUG_LOG("Pool chain destroyed successfully.");
#endif
}

MemoryPointer* mem_pointer_create(const char* var_name, size_t size_hint) {
    if (!var_name) {
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("mem_pointer_create: NULL variable name.");
#endif
        return NULL;
    }

    MemoryPointer* ptr = malloc(sizeof(MemoryPointer));

    if (!ptr) {
        g_oom_handler(sizeof(MemoryPointer));
        return NULL;
    }

    /* copy variable name */
    size_t name_len = strlen(var_name) + 1;
    ptr->variable_name = malloc(name_len);

    if (!ptr->variable_name) {
        free(ptr);
        g_oom_handler(name_len);
        return NULL;
    }

    memcpy(ptr->variable_name, var_name, name_len);
    ptr->container = NULL;

#ifdef DEBUG_MEMORY_MANAGER
    DEBUG_LOG("Pointer created: %s (hint: %zu bytes).", var_name, size_hint);
#endif
    return ptr;
}

bool mem_pointer_allocate(MemoryPointer* ptr, size_t size, MemoryPool* pool) {
    /* parameter validation with error codes */
    if (!ptr || !pool) {
        errno = EINVAL;
        DEBUG_LOG("mem_pointer_allocate: NULL parameter.");
        return false;
    }

    if (size == 0) {
        errno = EINVAL;
        DEBUG_LOG("mem_pointer_allocate: zero size requested.");
        return false;
    }

    /* align size for memory alignment */
    size = align_size(size);

    /* if we can't even align properly, fail fast */
    if (size == 0) {
        errno = EOVERFLOW;
        DEBUG_LOG("mem_pointer_allocate: size alignment overflow.");
        return false;
    }

    MEM_LOCK(pool);

    /* handle existing container */
    if (ptr->container) {
        MemoryContainer* existing = ptr->container;
        bool existing_released = false;
        bool existing_destroyed = false;

        /* container fits and is exclusively owned */
        if (existing->size >= size && REF_GET(existing) == 1) {
            MEM_UNLOCK(pool);
            return true;
        }

        /* container fits but is shared */
        if (existing->size >= size) {
            MemoryContainer* new_container = mem_container_create(
                mem_compute_hash(ptr->variable_name), size);

            if (!new_container) {
                MEM_UNLOCK(pool);
                errno = ENOMEM;
                return false;
            }

            /* copy data if source exists */
            if (existing->data && new_container->data) {
                size_t copy_size = existing->size < size ? existing->size : size;
                memcpy(new_container->data, existing->data, copy_size);
            }

            /* decrement old container's ref count */
            int remaining_refs = REF_DEC(existing);
            existing_released = true;

            /* remove from pool but don't destroy yet */
            if (remaining_refs <= 0)
                existing_destroyed = remove_container_from_pool(pool, existing, false);

            /* add new container to pool with capacity check */
            if (pool->count >= pool->capacity && !grow_pool_capacity(pool)) {
                /* restore existing container if it was removed */
                if (existing_destroyed) {
                    if (pool->count >= pool->capacity && !grow_pool_capacity(pool))
                        mem_container_destroy(existing);
                    else {
                        existing->ref_count = 1;
                        pool->containers[pool->count++] = existing;
                    }
                }
                else if (existing_released)
                    REF_INC(existing);

                /* clean up failed new container */
                mem_container_destroy(new_container);
                MEM_UNLOCK(pool);
                errno = ENOMEM;
                return false;
            }

            /* add new container to pool successfully */
            pool->containers[pool->count++] = new_container;
            ptr->container = new_container;

            /* now safe to destroy old container if it was removed */
            if (existing_destroyed)
                mem_container_destroy(existing);

            MEM_UNLOCK(pool);

#ifdef DEBUG_MEMORY_MANAGER
            DEBUG_LOG("COW allocation: %zu bytes for %s (from shared container).",
                size, ptr->variable_name);
#endif
            return true;
        }

        /* container doesn't fit, release it */
        int remaining_refs = REF_DEC(existing);

        if (remaining_refs <= 0)
            remove_container_from_pool(pool, existing, true);
        ptr->container = NULL;
    }

    /* try to reuse orphaned container */
    MemoryContainer* best_fit = NULL;
    size_t best_fit_index = 0;
    size_t best_fit_waste = SIZE_MAX;

    for (size_t i = 0; i < pool->count; i++) {
        MemoryContainer* candidate = pool->containers[i];

        if (!candidate || candidate->ref_count != 0)
            continue;

        /* candidate must be at least the requested size */
        if (candidate->size >= size) {
            size_t waste = candidate->size - size;

            /* perfect fit, use it immediately */
            if (waste == 0) {
                best_fit = candidate;
                best_fit_index = i;
                break;
            }

            /* track best fit with smallest waste */
            if (waste < best_fit_waste) {
                best_fit = candidate;
                best_fit_index = i;
                best_fit_waste = waste;
            }
        }
    }

    /* reuse orphaned container */
    if (best_fit) {
        best_fit->ref_count = 1;
        ptr->container = best_fit;

        /* zero memory for security when reusing */
        if (best_fit->data)
            zero_memory(best_fit->data, best_fit->size);
        MEM_UNLOCK(pool);

#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("Reused orphaned container %p (size: %zu) for %s, waste: %zu bytes.",
            (void*)best_fit->address, best_fit->size,
            ptr->variable_name, best_fit_waste);
#endif
        return true;
    }

    /* create a new container */
    size_t address = mem_compute_hash(ptr->variable_name ? ptr->variable_name : "");
    MemoryContainer* container = mem_container_create(address, size);

    if (!container) {
        MEM_UNLOCK(pool);
        errno = ENOMEM;
        return false;
    }

    /* add to pool with capacity check */
    if (pool->count >= pool->capacity && !grow_pool_capacity(pool)) {
        mem_container_destroy(container);
        MEM_UNLOCK(pool);
        errno = ENOMEM;
        return false;
    }

    /* success addition of container to the pool */
    pool->containers[pool->count++] = container;
    ptr->container = container;

    MEM_UNLOCK(pool);

#ifdef DEBUG_MEMORY_MANAGER
    DEBUG_LOG("Allocated new container: %zu bytes for %s (address: 0x%zx).",
        size, ptr->variable_name, address);
#endif

    return true;
}

bool remove_container_from_pool(MemoryPool* pool, MemoryContainer* container, bool destroy_if_last_ref) {
    /* validate inputs */
    if (!pool || !container) {
        errno = EINVAL;
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("remove_container_from_pool: NULL pool or container.");
#endif
        return false;
    }

    if (!pool->containers) {
        errno = EINVAL;
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("remove_container_from_pool: pool has NULL containers array.");
#endif
        return false;
    }

    bool found = false;
    size_t found_index = 0;

    /* find container in pool (O(n) search) */
    for (size_t i = 0; i < pool->count; i++) {
        if (pool->containers[i] == container) {
            found = true;
            found_index = i;
            break;
        }
    }

    if (!found) {
        errno = ENOENT;
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("remove_container_from_pool: container %p not found in pool.",
            (void*)container->address);
#endif
        return false;
    }

    /* remove container using swap-with-last technique (O(1) removal) */
    size_t last_index = pool->count - 1;

    /* swap with last element unless it's already the last */
    if (found_index != last_index)
        pool->containers[found_index] = pool->containers[last_index];

    /* clear the last position */
    pool->containers[last_index] = NULL;
    pool->count--;

#ifdef DEBUG_MEMORY_MANAGER
    DEBUG_LOG("Removed container %p from pool (index %zu). Pool count: %zu.",
        (void*)container->address, found_index, pool->count);
#endif

    const size_t shrink_threshold = SHRINK_POOL_THRESHOLD;
    const size_t min_capacity = MIN_POOL_CAPACITY;

    if (pool->capacity > min_capacity &&
        pool->count * shrink_threshold < pool->capacity) {
        size_t new_capacity = pool->capacity / 2;

        /* ensure new capacity doesn't go below minimum */
        if (new_capacity < min_capacity)
            new_capacity = min_capacity;

        /* ensure new capacity is at least current count */
        if (new_capacity < pool->count)
            new_capacity = pool->count;

        /* only reallocate if there's significant space savings */
        if (new_capacity < pool->capacity) {
            if (new_capacity > SIZE_MAX / sizeof(MemoryContainer*)) {
#ifdef DEBUG_MEMORY_MANAGER
                DEBUG_LOG("Warning: Shrink size calculation would overflow.");
#endif
                /* Continue without shrinking */
            }
            else {
                size_t new_size = new_capacity * sizeof(MemoryContainer*);
                MemoryContainer** new_array = realloc(pool->containers, new_size);

                if (new_array) {
                    pool->containers = new_array;
                    pool->capacity = new_capacity;

#ifdef DEBUG_MEMORY_MANAGER
                    DEBUG_LOG("Pool shrunk: capacity %zu -> %zu (count: %zu, savings: %zu bytes).",
                        pool->capacity, new_capacity, pool->count,
                        (pool->capacity - new_capacity) * sizeof(MemoryContainer*));
#endif
                }
                else {
#ifdef DEBUG_MEMORY_MANAGER
                    DEBUG_LOG("Warning: Pool shrink realloc failed, keeping current capacity.");
#endif
                }
            }
        }
    }

    /* handle container destruction if requested */
    bool should_destroy = destroy_if_last_ref;

    /* check if container is truly unreferenced */
    if (should_destroy) {
        int current_refs = REF_GET(container);

        if (current_refs > 0) {
#ifdef DEBUG_MEMORY_MANAGER
            DEBUG_LOG("Warning: Container %p has %d refs but destroy requested.",
                (void*)container->address, current_refs);
#endif
            should_destroy = false;
        }
        /* negative ref count indicates corruption */
        else if (current_refs < 0) {
#ifdef DEBUG_MEMORY_MANAGER
            DEBUG_LOG("Error: Container %p has negative ref count: %d.",
                (void*)container->address, current_refs);
#endif
            should_destroy = false;
            errno = EFAULT;
        }
    }

    if (should_destroy) {
        mem_container_destroy(container);
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("Container %p destroyed after removal from pool.",
            (void*)container->address);
#endif
    }

    return true;
}

void mem_pointer_destroy(MemoryPointer* ptr, MemoryPool* pool) {
    if (!ptr) return;

#ifdef DEBUG_MEMORY_MANAGER
    const char* var_name = ptr->variable_name ? ptr->variable_name : "<unnamed>";
    DEBUG_LOG("Destroying pointer: %s.", var_name);
#endif

    /* handle case where pool is NULL  */
    if (!pool) {
        if (ptr->container) {
            if (REF_DEC(ptr->container) <= 0)
                mem_container_destroy(ptr->container);
            
            ptr->container = NULL;
        }

        /* clean up pointer resources */
        if (ptr->variable_name) {
            zero_memory(ptr->variable_name, strlen(ptr->variable_name));
            free(ptr->variable_name);
        }

        zero_memory(ptr, sizeof(MemoryPointer));
        free(ptr);
        return;
    }

    MemoryContainer* container_to_destroy = NULL;
    MEM_LOCK(pool);

    /* decrement reference count atomically */
    if (ptr->container) {
        if (REF_DEC(ptr->container) <= 0) {
            container_to_destroy = ptr->container;

            /* remove from pool but don't destroy yet */
            if (!remove_container_from_pool(pool, container_to_destroy, false)) {
#ifdef DEBUG_MEMORY_MANAGER
                DEBUG_LOG("Warning: Container %p not found in pool during destruction.",
                    (void*)container_to_destroy);
#endif
                container_to_destroy = NULL;
            }
        }

        ptr->container = NULL;
    }

    MEM_UNLOCK(pool);

    /* destroy container outside lock to reduce contention */
    if (container_to_destroy)
        mem_container_destroy(container_to_destroy);

    /* clean up pointer metadata */
    if (ptr->variable_name) {
        zero_memory(ptr->variable_name, strlen(ptr->variable_name));
        free(ptr->variable_name);
    }

    zero_memory(ptr, sizeof(MemoryPointer));
    free(ptr);
}

/**
 * @brief Finds container by address with binary search on sorted addresses.
 *
 * Note: Requires containers array to be sorted by address.
 * For O(log n) lookup, call sort_containers_by_address() first.
 *
 * @param pool MemoryPool to search
 * @param address Address to find
 * @return MemoryContainer* if found, NULL otherwise
 */
static MemoryContainer* find_container_by_address(const MemoryPool* pool, size_t address) {
    if (!pool || !pool->containers || address == 0)
        return NULL;

    /* linear search (O(n)), good enough for the small pools */
    for (size_t i = 0; i < pool->count; i++) {
        if (pool->containers[i] && pool->containers[i]->address == address)
            return pool->containers[i];
    }

    return NULL;
}

/**
 * @brief Sorts containers by address for O(log n) lookups.
 *
 * Call this periodically or when pool size changes significantly.
 *
 * @param pool MemoryPool to sort
 */
static void sort_containers_by_address(MemoryPool* pool) {
    if (!pool || pool->count < 2)
        return;

    MEM_LOCK(pool);

    /* simple insertion sort algorithm */
    for (size_t i = 1; i < pool->count; i++) {
        MemoryContainer* key = pool->containers[i];
        size_t j = i;

        while (j > 0 && pool->containers[j - 1]->address > key->address) {
            pool->containers[j] = pool->containers[j - 1];
            j--;
        }

        pool->containers[j] = key;
    }

    MEM_UNLOCK(pool);

#ifdef DEBUG_MEMORY_MANAGER
    DEBUG_LOG("Sorted %zu containers by address.", pool->count);
#endif
}

MemoryContainer* mem_container_create(size_t address, size_t size) {
    if (size == 0) {
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("mem_container_create: zero size.");
#endif
        return NULL;
    }

    MemoryContainer* container = malloc(sizeof(MemoryContainer));

    if (!container) {
        g_oom_handler(sizeof(MemoryContainer));
        return NULL;
    }

    /* allocate actual memory for data */
    size = align_size(size);
    void* data = malloc(size);

    if (!data) {
        free(container);
        g_oom_handler(size);
        return NULL;
    }

    /* initialize the memory to zero for safety */
    zero_memory(data, size);
    container->address = address;
    container->size = size;
    container->ref_count = 1;
    container->data = data;

    DEBUG_LOG("Container created: address=%zu, size=%zu.", address, size);
    return container;
}

bool mem_pool_add_container(MemoryPool* pool, MemoryContainer* container) {
    if (!pool || !container) {
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("mem_pool_add_container: NULL parameter.");
#endif
        return false;
    }

    MEM_LOCK(pool);

    /* check for duplicates */
    for (size_t i = 0; i < pool->count; i++) {
        if (pool->containers[i] == container) {
            MEM_UNLOCK(pool);
#ifdef DEBUG_MEMORY_MANAGER
            DEBUG_LOG("Container %p already in pool.", (void*)container);
#endif
            return false;
        }
    }

    /* check if we need to grow the pool */
    if (pool->count >= pool->capacity) {
        if (!grow_pool_capacity(pool)) {
            MEM_UNLOCK(pool);
            return false;
        }
    }

    pool->containers[pool->count++] = container;
    MEM_UNLOCK(pool);
#ifdef DEBUG_MEMORY_MANAGER
    DEBUG_LOG("Container added to pool, count=%zu.", pool->count);
#endif
    return true;
}

void mem_container_destroy(MemoryContainer* container) {
    if (!container)
        return;

#ifdef DEBUG_MEMORY_MANAGER
    DEBUG_LOG("Destroying container: address=%zu, size=%zu, refs=%d.",
        container->address, container->size, container->ref_count);
#endif

    /* clear sensitive data before freeing */
    if (container->data) {
        zero_memory(container->data, container->size);
        free(container->data);
        container->data = NULL;
    }

    /* clear container structure */
    zero_memory(container, sizeof(MemoryContainer));
    free(container);
}

size_t mem_compute_hash(const char* str) {
    if (!str)
        return 0;

    /* FNV-1a 64-bit hash algorithm */
    const size_t FNV_prime = 0x100000001b3ULL;
    const size_t FNV_offset = 0xcbf29ce484222325ULL;

    size_t hash = FNV_offset;
    const unsigned char* s = (const unsigned char*)str;

    while (*s) {
        hash ^= *s++;
        hash *= FNV_prime;
    }

    return hash;
}

size_t mem_pool_get_count(const MemoryPool* pool) {
    if (!pool)
        return 0;

    MEM_LOCK(pool);
    size_t count = pool->count;

    MEM_UNLOCK(pool);
    return count;
}

size_t mem_pool_get_total_bytes(const MemoryPool* pool) {
    if (!pool)
        return 0;

    MEM_LOCK(pool);
    size_t total = 0;

    for (size_t i = 0; i < pool->count; i++) {
        if (pool->containers[i])
            total += pool->containers[i]->size;
    }

    MEM_UNLOCK(pool);
    return total;
}

MemoryArena* mem_arena_create(size_t arena_size) {
    if (arena_size == 0) {
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("mem_arena_create: zero size.");
#endif
        return NULL;
    }

    /* align arena size */
    arena_size = align_size(arena_size);
    MemoryArena* arena = malloc(sizeof(MemoryArena));

    if (!arena) {
        g_oom_handler(sizeof(MemoryArena));
        return NULL;
    }

    arena->memory = malloc(arena_size);

    if (!arena->memory) {
        free(arena);
        g_oom_handler(arena_size);
        return NULL;
    }

    /* initialize memory to zero */
    zero_memory(arena->memory, arena_size);

    arena->size = arena_size;
    arena->used = 0;
    arena->next = NULL;

    DEBUG_LOG("Arena created: %zu bytes.", arena_size);
    return arena;
}

void* mem_arena_alloc(MemoryArena* arena, size_t size) {
    if (!arena || size == 0) return NULL;
    size = align_size(size);
    MemoryArena* current = arena;

    while (1) {
        if (current->used + size <= current->size) {
            void* ptr = (char*)current->memory + current->used;
            current->used += size;
            return ptr;
        }

        if (!current->next) {
            size_t new_size = current->size * 2;
            if (size > new_size) new_size = size * 2;
            current->next = mem_arena_create(new_size);
            if (!current->next) return NULL;
        }

        current = current->next;
    }
}

void mem_arena_destroy(MemoryArena* arena) {
    while (arena) {
        MemoryArena* next = arena->next;

        /* clear all arena memory for security */
        if (arena->memory) {
            zero_memory(arena->memory, arena->size);
            free(arena->memory);
        }

        zero_memory(arena, sizeof(MemoryArena));
        free(arena);
        arena = next;
    }
    
#ifdef DEBUG_MEMORY_MANAGER
    DEBUG_LOG("Arena is destroyed.");
#endif
}

#ifdef DEBUG_MEMORY_MANAGER

bool mem_pool_validate(const MemoryPool* pool) {
    if (!pool) {
        DEBUG_LOG("Validation failed: NULL pool.");
        return false;
    }

    MEM_LOCK(pool);
    bool valid = true;

    /* check pool structure */
    if (!pool->containers && pool->capacity > 0) {
        DEBUG_LOG("Validation failed: containers NULL but capacity > 0.");
        valid = false;
        goto done;
    }

    if (pool->count > pool->capacity) {
        DEBUG_LOG("Validation failed: count (%zu) > capacity (%zu).",
            pool->count, pool->capacity);
        valid = false;
        goto done;
    }

    /* validate each container */
    for (size_t i = 0; i < pool->count; i++) {
        MemoryContainer* container = pool->containers[i];

        if (!container) {
            DEBUG_LOG("Validation failed: NULL container at index %zu.", i);
            valid = false;
            continue;
        }

        if (container->ref_count <= 0) {
            DEBUG_LOG("Validation failed: container %zu has invalid ref_count %d.",
                container->address, container->ref_count);
            valid = false;
        }

        if (container->data == NULL && container->size > 0) {
            DEBUG_LOG("Validation failed: container %zu has NULL data but size %zu.",
                container->address, container->size);
            valid = false;
        }

        if (container->data != NULL && container->size == 0) {
            DEBUG_LOG("Validation failed: container %zu has data but zero size.",
                container->address);
            valid = false;
        }
    }

done:
    MEM_UNLOCK(pool);

    if (valid)
        DEBUG_LOG("Pool validation passed.");
    return valid;
}

void mem_pool_dump(const MemoryPool* pool, bool detailed) {
    if (!pool) {
        printf("Pool is NULL.\n");
        return;
    }

    MEM_LOCK(pool);

    printf("=== Memory Pool Dump ===\n");
    printf("Containers: %zu/%zu\n", pool->count, pool->capacity);
    printf("Total bytes: %zu\n", mem_pool_get_total_bytes(pool));

    if (detailed) {
        printf("\nContainers:\n");
        printf("IDX  Address         Size      Refs  Data Pointer\n");
        printf("---  --------------- --------- ----  ------------\n");

        for (size_t i = 0; i < pool->count; i++) {
            MemoryContainer* container = pool->containers[i];
            if (container) {
                printf("%3zu  %15zu %9zu %4d  %p\n",
                    i, container->address, container->size,
                    container->ref_count, container->data);
            }
            else {
                printf("%3zu  [NULL]\n", i);
            }
        }
    }

    MEM_UNLOCK(pool);
    printf("=== End Dump ===\n");
}

#endif

void mem_set_oom_handler(void (*handler)(size_t requested)) {
    if (handler)  g_oom_handler = handler;
    else g_oom_handler = default_oom_handler;
}

bool grow_pool_capacity(MemoryPool* pool) {
    /* validate input */
    if (!pool) {
        errno = EINVAL;
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("grow_pool_capacity: NULL pool pointer.");
#endif
        return false;
    }

    if (!pool->containers && pool->capacity > 0) {
        errno = EFAULT;
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("grow_pool_capacity: inconsistent pool state.");
#endif
        return false;
    }

    /* calculate new capacity with overflow protection */
    size_t new_capacity;

    /* first allocation, use sensible default */
    if (pool->capacity == 0) {
        new_capacity = MEM_POOL_DEFAULT_CAPACITY;
        if (new_capacity == 0)
            new_capacity = MEM_POOL_DEFAULT_CAPACITY;
    }
    else {
        /* check for overflow in multiplication */
        if (pool->capacity > SIZE_MAX / 2) {
            errno = EOVERFLOW;
#ifdef DEBUG_MEMORY_MANAGER
            DEBUG_LOG("grow_pool_capacity: capacity %zu would overflow when doubled.",
                pool->capacity);
#endif
            return false;
        }

        new_capacity = pool->capacity * 2;

        /* ensure we grow by at least a minimum amount for small pools */
        if (new_capacity < 8)
            new_capacity = 8;
    }

    /* check for overflow in size calculation */
    if (new_capacity > SIZE_MAX / sizeof(MemoryContainer*)) {
        errno = EOVERFLOW;
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("grow_pool_capacity: new size calculation would overflow.");
#endif
        return false;
    }

    size_t new_size = new_capacity * sizeof(MemoryContainer*);
    size_t old_size = pool->capacity * sizeof(MemoryContainer*);

#ifdef DEBUG_MEMORY_MANAGER
    DEBUG_LOG("Growing pool: %zu -> %zu containers (%zu -> %zu bytes).",
        pool->capacity, new_capacity, old_size, new_size);
#endif

    /* allocate new array */
    MemoryContainer** new_containers;

    /* reallocate existing array */
    if (pool->containers)
        new_containers = realloc(pool->containers, new_size);
    else
        /* first allocation */
        new_containers = malloc(new_size);

    /* out of memory thrown, call handler with requested size */
    if (!new_containers) {
        g_oom_handler(new_size);
        errno = ENOMEM;
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("grow_pool_capacity: failed to allocate %zu bytes.", new_size);
#endif
        return false;
    }

    /* zero the newly allocated portion safely */
    if (new_capacity > pool->capacity) {
        size_t zero_start = pool->capacity;
        size_t zero_count = new_capacity - pool->capacity;

        /* use memset for better performance */
        memset(&new_containers[zero_start], 0,
            zero_count * sizeof(MemoryContainer*));
    }

    /* update pool structure atomically */
    pool->containers = new_containers;
    pool->capacity = new_capacity;

#ifdef DEBUG_MEMORY_MANAGER
    DEBUG_LOG("Pool grown successfully to capacity %zu.", new_capacity);
#endif

    return true;
}

static size_t align_size(size_t size) {
    size_t alignment = MEM_ALIGNMENT;
    size_t remainder = size % alignment;

    if (remainder != 0)
        size += alignment - remainder;
    return size;
}

static void zero_memory(void* ptr, size_t size) {
    if (ptr && size > 0)
        memset(ptr, 0, size);
}
