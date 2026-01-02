# libmemkit

**libmemkit** is a high-performance, security-oriented memory management library for C systems programming.<br/>
It provides **reference-counted smart pointers**, **memory pooling**, and **arena allocators**, with optional **thread 
safety**,<br/> **copy-on-write semantics**, and **deterministic container tracking**. The design emphasizes predictable 
performance,<br/> low fragmentation, and defensive memory hygiene suitable for long-running or security-sensitive applications.

## Key Features

1. **Reference-Counted Smart Pointers**
- Automatic lifetime management via atomic or non-atomic refcounts
- Copy-on-write (COW) semantics for shared containers
- Deterministic container identity via FNV-1a hashing

2. **Memory Pooling**
- Centralized tracking of all allocations
- O(1) container removal (swap-with-last)
- Automatic pool growth and shrink heuristics
- Orphaned container reuse with best-fit selection

3. **Arena Allocators**
- O(1) bump allocation
- Excellent cache locality
- Bulk deallocation with a single call
- Automatic arena chaining for large workloads

3. **Thread Safety (Optional)**
- Compile-time configurable (MEM_THREAD_SAFE)
- Mutex-protected pool operations
- Atomic reference counting when enabled

4. **Security-First Design**
- All freed memory is zeroed before release
- Containers are wiped before destruction
- Defensive validation in debug builds

5. **Debug Infrastructure**
- Pool validation and integrity checks
- Detailed pool and container dumps
- Extensive internal consistency logging

6. **Custom OOM Handling**
- User-defined allocation failure hooks
- Centralized failure reporting

## Quick Start

```c
#include "memkit.h"
#include <stdio.h>

int main(void) {
    MemoryPool pool;
    if (!mem_pool_init(&pool, 16)) {
        fprintf(stderr, "Failed to initialize memory pool.\n");
        return 1;
    }

    MemoryPointer* buffer = mem_pointer_create("data_buffer", 1024);
    if (!mem_pointer_allocate(buffer, 1024, &pool)) {
        fprintf(stderr, "Allocation failed.\n");
        return 1;
    }

    // Use allocated memory
    int* data = (int*)buffer->container->data;
    data[0] = 42;
    printf("Allocated %zu bytes, stored: %d.\n", 
           buffer->container->size, data[0]);

    // Cleanup
    mem_pointer_destroy(buffer, &pool);
    mem_pool_destroy(&pool);
    return 0;
}
```
## Core Components

### MemoryPool
The central registry for all active containers.

* **Responsibilities**:
   - Tracks container ownership and lifetime
   - Enables reuse of orphaned containers
   - Handles pool growth, shrinkage, and cleanup

### MemoryPointer

- A smart pointer wrapper that references a `MemoryContainer`.
- Automatically increments/decrements reference counts
- Triggers copy-on-write when modifying shared containers
- Human-readable variable names aid debugging and diagnostics

### MemoryContainer
The fundamental allocation unit managed by the library.

- Owns a contiguous block of heap memory
- Tracks size, reference count, and deterministic address
- Destroyed automatically when reference count reaches zero

### MemoryArena
A high-performance allocator for short-lived or bulk allocations.

- Bump-pointer allocation
- No per-allocation metadata
- Entire arena freed in one operation

### Configuration
All configuration is compile-time driven via macros:

```c
#define MEM_POOL_DEFAULT_CAPACITY 32   /* initial pool size */
#define MEM_ALIGNMENT 8                /* memory alignment */
#define MEM_THREAD_SAFE 1              /* enable thread safety */
#define DEBUG_MEMORY_MANAGER 1         /* enable debug features */
```

### Advanced Usage
#### Arena Allocation<br/>
```c
MemoryArena* arena = mem_arena_create(4096);
int* array = mem_arena_alloc(arena, 100 * sizeof(int));
// All allocations freed with single call:
mem_arena_destroy(arena);
```

#### Debug Features<br/>
```c
#ifdef DEBUG_MEMORY_MANAGER
mem_pool_validate(&pool);      /* integrity check */
mem_pool_dump(&pool, true);    /* detailed diagnostics */
#endif
```

#### Custom Error Handling<br/>
```c
void my_oom_handler(size_t requested) {
    fprintf(stderr, "CRITICAL: Failed to allocate %zu bytes.\n", requested);
    // Emergency cleanup or alerting
}

mem_set_oom_handler(my_oom_handler);
```

### Performance Characteristics
- **Allocation**: O(n) worst-case for container search, O(1) with reuse
- **Deallocation**: O(1) for pointer destruction, O(n) for pool cleanup
- **Memory Overhead**: ~32 bytes per container + alignment padding
- **Thread Safety**: Minimal lock contention with scope-optimized locking

### Security Features
- All freed memory is zeroed before release
- Automatic detection of use-after-free via reference counting
- Container validation in debug mode
- Customizable out-of-memory handlers

### Best Practices
1. Initialize pools early with estimated capacity to minimize reallocations
2. Use arenas for temporary, related allocations (parsing, rendering frames)
3. Enable debug mode during development to catch memory issues
4. Set appropriate alignment for your target architecture (SIMD, cache lines)
5. Implement custom OOM handlers for graceful degradation
