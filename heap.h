#ifndef PROJECT1_HEAP_H
#define PROJECT1_HEAP_H
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include "custom_unistd.h"

#define PAGE_SIZE 4096
#define MINIMAL_MALLOC_MEM 1
#define FENCE_LENGTH 2
#define BLOCK_SIZE(size) (sizeof(struct block_t) + size + 2 * FENCE_LENGTH)
#define INITIALIZED_NUMBER 1234
struct heap_t {
    struct block_t* phead;
    struct block_t* ptail;
    struct block_t* pfree;
    int initialized;
    size_t pages;
    size_t headers;
    size_t control_sum;
}__attribute__((packed));

struct block_t {
    struct block_t* pnext;
    struct block_t* pprev;
    void *memory;
    size_t size;
    short free;
    size_t control_sum;
}__attribute__((packed));
size_t calculate_block_control_sum(struct block_t * block);
void dump_memory2();
void dump_memory_rev();
int check_fences();
size_t calculate_heap_control_sum();
int heap_setup(void);
void heap_clean(void);
void* heap_malloc(size_t size);
void* heap_calloc(size_t number, size_t size);
void* heap_realloc(void* memblock, size_t count);
void  heap_free(void* memblock);

enum pointer_type_t
{
    pointer_null,
    pointer_heap_corrupted,
    pointer_control_block,
    pointer_inside_fences,
    pointer_inside_data_block,
    pointer_unallocated,
    pointer_valid
};




size_t   heap_get_largest_used_block_size(void);
enum pointer_type_t get_pointer_type(const void* const pointer);
int heap_validate(void);

void* heap_malloc_aligned(size_t count);
void* heap_calloc_aligned(size_t number, size_t size);
void* heap_realloc_aligned(void* memblock, size_t size);

#endif //PROJECT1_HEAP_H
