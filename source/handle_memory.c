#include "handle_memory.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>

#if MEM_THREAD_SAFE
#include <pthread.h>
static pthread_mutex_t g_pool_mutex = PTHREAD_MUTEX_INITIALIZER;
#define LOCK_POOL() pthread_mutex_lock(&g_pool_mutex)
#define UNLOCK_POOL() pthread_mutex_unlock(&g_pool_mutex)
#else
#define LOCK_POOL() (void)0
#define UNLOCK_POOL() (void)0
#endif

#ifdef DEBUG_MEMORY
#define DEBUG_LOG(fmt, ...) fprintf(stderr, "[MEM] " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_LOG(...) (void)0
#endif

static MemoryContainer* find_container_by_address(const MemoryPool* pool, size_t address);
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
    if (!pool) {
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("mem_pool_init: NULL pool pointer.");
#endif
        return false;
    }

    if (initial_capacity == 0)
        initial_capacity = MEM_POOL_DEFAULT_CAPACITY;

    LOCK_POOL();
    pool->containers = calloc(initial_capacity, sizeof(MemoryContainer*));

    if (!pool->containers) {
        UNLOCK_POOL();
        g_oom_handler(initial_capacity * sizeof(MemoryContainer*));
        return false;
    }

    pool->capacity = initial_capacity;
    pool->count = 0;
    pool->next = NULL;
    UNLOCK_POOL();
#ifdef DEBUG_MEMORY_MANAGER
    DEBUG_LOG("Pool initialized with capacity %zu.", initial_capacity);
#endif
    return true;
}

void mem_pool_destroy(MemoryPool* pool) {
    if (!pool) return;
    MemoryPool* current = pool;
    MemoryPool* next_pool = NULL;

    while (current) {
        LOCK_POOL();

        /* debug check before destruction */
#ifdef DEBUG_MEMORY_MANAGER
        if (current->count > 0) {
            for (size_t i = 0; i < current->count; i++) {
                if (current->containers[i]) {
                    DEBUG_LOG("Warning: Non-NULL container at index %zu before destruction.", i);
                }
            }
        }
#endif

        /* destroy all containers */
        if (current->containers) {
            for (size_t i = current->count; i-- > 0; ) {
                MemoryContainer* container = current->containers[i];
                if (container) mem_container_destroy(container);
            }

            /* zero the containers array for security */
            zero_memory(current->containers,
                current->count * sizeof(MemoryContainer*));

            free(current->containers);
            current->containers = NULL;
        }

        /* store next pointer before clearing current */
        next_pool = current->next;

        /* clear pool metadata */
        current->capacity = 0;
        current->count = 0;
        current->next = NULL;
        UNLOCK_POOL();

        /* zero the pool structure itself */
        zero_memory(current, sizeof(MemoryPool));
        current = next_pool;
    }

#ifdef DEBUG_MEMORY_MANAGER
    DEBUG_LOG("Pool chain destroyed.");
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
    if (!ptr || !pool) {
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("mem_pointer_allocate: NULL parameter.");
#endif
        return false;
    }

    if (size == 0) {
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("mem_pointer_allocate: zero size requested.");
#endif
        return false;
    }

    LOCK_POOL();
    size = align_size(size);

    /* check if pointer already has a container */
    if (ptr->container) {
        if (ptr->container->size >= size && ptr->container->ref_count == 1) {
#ifdef DEBUG_MEMORY_MANAGER
            DEBUG_LOG("Reusing exclusive container %p for %s.",
                (void*)ptr->container->address, ptr->variable_name);
#endif

            UNLOCK_POOL();
            return true;
        }

        /* container is shared but size is sufficient */
        if (ptr->container->size >= size && ptr->container->ref_count > 1) {
#ifdef DEBUG_MEMORY_MANAGER
            DEBUG_LOG("Container shared (%d refs), creating new one for %s.",
                ptr->container->ref_count, ptr->variable_name);
#endif

            /* decrement ref count but do not remove from pool */
            ptr->container->ref_count--;
            ptr->container = NULL;
        }
        else {
            /* Size insufficient or container needs replacement */
#ifdef DEBUG_MEMORY_MANAGER
            DEBUG_LOG("%s container insufficient: %zu < %zu bytes or needs replacement.",
                ptr->variable_name, ptr->container->size, size);
#endif

            /* decrement ref count */
            ptr->container->ref_count--;

            /* if this was the last reference, find and remove from pool */
            if (ptr->container->ref_count <= 0) {
                bool found = false;

                for (size_t i = 0; i < pool->count; i++) {
                    /* move last element to this position */
                    if (pool->containers[i] == ptr->container) {
                        pool->containers[i] = pool->containers[pool->count - 1];
                        pool->count--;
                        found = true;

                        /* destroy the orphaned container */
                        mem_container_destroy(ptr->container);
                        break;
                    }
                }

                if (!found) {
#ifdef DEBUG_MEMORY_MANAGER
                    DEBUG_LOG("Warning: orphaned container not found in pool");
#endif
                    mem_container_destroy(ptr->container);
                }
            }

            ptr->container = NULL;
        }
    }

    /* try to find an existing container that meets our needs */
    MemoryContainer* existing_container = NULL;
    size_t best_fit_index = 0;
    bool best_fit_found = false;

    for (size_t i = 0; i < pool->count; i++) {
        MemoryContainer* candidate = pool->containers[i];

        /* found an orphaned container that can be reused */
        if (candidate && candidate->size >= size && candidate->ref_count == 0) {
            if (!existing_container || candidate->size < existing_container->size) {
                existing_container = candidate;
                best_fit_index = i;
                best_fit_found = true;
            }
        }
    }

    if (best_fit_found) {
        /* Reuse existing orphaned container */
        DEBUG_LOG("Reusing orphaned container %p (size: %zu) for %s.",
            (void*)existing_container->address, existing_container->size,
            ptr->variable_name);

        /* update container metadata */
        existing_container->ref_count = 1;

        /* clear old data if needed */
        if (existing_container->data)
            zero_memory(existing_container->data, existing_container->size);

        ptr->container = existing_container;
        UNLOCK_POOL();
        return true;
    }

    /* create new container */
    size_t address = mem_compute_hash(ptr->variable_name);
    MemoryContainer* container = mem_container_create(address, size);

    if (!container) {
        UNLOCK_POOL();
        return false;
    }

    /* add to the pool */
    if (!mem_pool_add_container(pool, container)) {
        mem_container_destroy(container);
        UNLOCK_POOL();
        return false;
    }

    ptr->container = container;
    UNLOCK_POOL();

    DEBUG_LOG("Allocated %zu bytes for %s at address %zu.",
        size, ptr->variable_name, address);
    return true;
}

static bool remove_container_from_pool(MemoryPool* pool, MemoryContainer* container) {
    for (size_t i = 0; i < pool->count; i++) {
        if (pool->containers[i] == container) {
            pool->containers[i] = pool->containers[pool->count - 1];
            pool->count--;

            /* shrink pool if mostly empty */
            if (pool->capacity > 64 && pool->count * 4 < pool->capacity) {
                size_t new_capacity = pool->capacity / 2;
                MemoryContainer** new_array = realloc(pool->containers,
                    new_capacity * sizeof(MemoryContainer*));

                if (new_array) {
                    pool->containers = new_array;
                    pool->capacity = new_capacity;
                }
            }

            return true;
        }
    }

    return false;
}

void mem_pointer_destroy(MemoryPointer* ptr, MemoryPool* pool) {
    if (!ptr)  return;
#ifdef DEBUG_MEMORY_MANAGER
    DEBUG_LOG("Destroying pointer: %s.", ptr->variable_name ? ptr->variable_name : "<unnamed>");
#endif
    MemoryContainer* container_to_destroy = NULL;

    /* update reference count and check if removal needed */
    if (ptr->container) {
        LOCK_POOL();

        ptr->container->ref_count--;
#ifdef DEBUG_MEMORY_MANAGER
        DEBUG_LOG("Container refs decreased to %d.", ptr->container->ref_count);
#endif

        if (ptr->container->ref_count <= 0) {
            /* mark for destruction, but do it outside lock */
            container_to_destroy = ptr->container;

            /* remove from pool while it have the lock */
            bool found = false;
            for (size_t i = 0; i < pool->count; i++) {
                if (pool->containers[i] == container_to_destroy) {
                    pool->containers[i] = pool->containers[pool->count - 1];
                    pool->count--;
                    found = true;
                    break;
                }
            }

            if (!found) {
#ifdef DEBUG_MEMORY_MANAGER
                DEBUG_LOG("Warning: container not found in pool.");
#endif
                container_to_destroy = NULL;
            }
        }

        UNLOCK_POOL();
    }

    /* destroy container outside of pool lock */
    if (container_to_destroy)
        mem_container_destroy(container_to_destroy);

    /* clean up pointer resources */
    if (ptr->variable_name) {
        zero_memory(ptr->variable_name, strlen(ptr->variable_name));
        free(ptr->variable_name);
    }

    zero_memory(ptr, sizeof(MemoryPointer));
    free(ptr);
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

    LOCK_POOL();

    /* check for duplicates */
    for (size_t i = 0; i < pool->count; i++) {
        if (pool->containers[i] == container) {
            UNLOCK_POOL();
#ifdef DEBUG_MEMORY_MANAGER
            DEBUG_LOG("Container %p already in pool.", (void*)container);
#endif
            return false;
        }
    }

    /* check if we need to grow the pool */
    if (pool->count >= pool->capacity) {
        if (!grow_pool_capacity(pool)) {
            UNLOCK_POOL();
            return false;
        }
    }

    pool->containers[pool->count++] = container;
    UNLOCK_POOL();
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

size_t mem_pool_get_count(MemoryPool* pool) {
    if (!pool)
        return 0;

    LOCK_POOL();
    size_t count = pool->count;

    UNLOCK_POOL();
    return count;
}

size_t mem_pool_get_total_bytes(const MemoryPool* pool) {
    if (!pool)
        return 0;

    LOCK_POOL();
    size_t total = 0;

    for (size_t i = 0; i < pool->count; i++) {
        if (pool->containers[i])
            total += pool->containers[i]->size;
    }

    UNLOCK_POOL();
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

    LOCK_POOL();
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
    UNLOCK_POOL();

    if (valid)
        DEBUG_LOG("Pool validation passed.");
    return valid;
}

void mem_pool_dump(const MemoryPool* pool, bool detailed) {
    if (!pool) {
        printf("Pool is NULL.\n");
        return;
    }

    LOCK_POOL();

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

    UNLOCK_POOL();
    printf("=== End Dump ===\n");
}

#endif

void mem_set_oom_handler(void (*handler)(size_t requested)) {
    if (handler)  g_oom_handler = handler;
    else g_oom_handler = default_oom_handler;
}

static MemoryContainer* find_container_by_address(const MemoryPool* pool, size_t address) {
    if (!pool || address == 0)
        return NULL;

    for (size_t i = 0; i < pool->count; i++) {
        if (pool->containers[i] && pool->containers[i]->address == address)
            return pool->containers[i];
    }

    return NULL;
}

static bool grow_pool_capacity(MemoryPool* pool) {
    size_t new_capacity = pool->capacity * 2;

    /* ensure minimum growth */
    if (new_capacity < 8)
        new_capacity = 8;

#ifdef DEBUG_MEMORY_MANAGER
    DEBUG_LOG("Growing pool capacity: %zu -> %zu.", pool->capacity, new_capacity);
#endif

    MemoryContainer** new_containers = realloc(pool->containers,
        new_capacity * sizeof(MemoryContainer*));
    if (!new_containers) {
        g_oom_handler(new_capacity * sizeof(MemoryContainer*));
        return false;
    }

    /* zero new memory */
    if (new_capacity > pool->capacity) {
        zero_memory(&new_containers[pool->capacity],
            (new_capacity - pool->capacity) * sizeof(MemoryContainer*));
    }

    pool->containers = new_containers;
    pool->capacity = new_capacity;
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

#if MEM_THREAD_SAFE
#include <pthread.h>
static pthread_mutex_t g_pool_mutex = PTHREAD_MUTEX_INITIALIZER;
#define LOCK_POOL() pthread_mutex_lock(&g_pool_mutex)
#define UNLOCK_POOL() pthread_mutex_unlock(&g_pool_mutex)
#else
#define LOCK_POOL() (void)0
#define UNLOCK_POOL() (void)0
#endif