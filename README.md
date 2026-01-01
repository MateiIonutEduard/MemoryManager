## Description

A professional, thread-safe memory management library for C systems programming.<br/> 
Provides smart pointers, memory pooling, and arena allocators with security-first design.

## Features

- **Smart Pointers** with automatic reference counting
- **Memory Pooling** for efficient allocation/deallocation
- **Arena Allocators** for bulk allocations with O(1) performance
- **Thread-Safe** operations with configurable locking
- **Security-Focused** with automatic memory zeroing
- **Debug Infrastructure** with validation and detailed logging
- **Smart Reuse** with best-fit container selection

## Quick Start

```c
#include "handle_memory.h"

int main() {
    MemoryPool pool;
    mem_pool_init(&pool, 16);
    
    MemoryPointer* ptr = mem_pointer_create("my_buffer", 1024);
    mem_pointer_allocate(ptr, 1024, &pool);
    
    // Use ptr->container->data...
    
    mem_pointer_destroy(ptr, &pool);
    mem_pool_destroy(&pool);
    return 0;
}
```
## Core Components

### MemoryPool
Central registry for tracking all memory allocations. Provides container <br/>management, reference counting, and automatic cleanup.

### MemoryPointer
Smart pointer wrapper that manages container references and <br/>automatic deallocation when references reach zero.

### MemoryArena
High-performance arena allocator for scenarios requiring bulk allocations. <br/>All arena memory is freed simultaneously on destruction.<br/>

### Configuration
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
