#include <string.h>
#include <stdbool.h>
#include "heap.h"



static struct heap_t *heap = NULL;

struct block_t *split_block(struct block_t *pBlock, size_t size);

void init_block(struct block_t *block_pos, size_t memory_size, struct block_t *prev, struct block_t *next);

int request_space(size_t pages);

struct block_t *find_first_fit();

size_t calculate_needed_pages(size_t size);

uint8_t *getNextPagePointer(uint8_t *pointer) {
    for (int i = 0;; ++i) {
        if (((intptr_t) pointer & (intptr_t) (PAGE_SIZE - 1)) == 0) return pointer;
        pointer++;
    }
}

void print_block(struct block_t *pblock) {
    for (uint8_t *character = (uint8_t *) pblock;
         character != ((uint8_t *) pblock + BLOCK_SIZE(pblock->size)); character++) {
        if (*((char *) character) == '#') printf("%c", *character);
        else printf(".");
    }
    printf("\n");
}

void dump_memory2() {
    int counter = 0;
    long long unsigned size = 0;
    long long unsigned total_size = 0;
    for (struct block_t *pblock = heap->phead; pblock != heap->ptail->pnext; pblock = pblock->pnext) {
        counter++;
        printf("%3d.", counter);
        printf("prev: %15p, ", (void *) pblock->pprev);
        printf("pointer: %15p, ", (void *) pblock);
        printf("next: %15p, ", (void *) pblock->pnext);
        printf("free: %d, ", pblock->free);
        printf("memory: %5zu, ", pblock->size);
        printf("total_size: %6zu\n", BLOCK_SIZE(pblock->size));
        size += pblock->size;
        total_size += BLOCK_SIZE(pblock->size);

    }
    printf("=====================\n");
    printf("TOTAL MEMORY SIZE: %llu\n", size);
    printf("TOTAL BLOCKS SIZE: %llu\n", total_size);

}

void dump_memory_rev() {
    int counter = 0;
    long long unsigned size = 0;
    long long unsigned total_size = 0;
    for (struct block_t *pblock = heap->ptail; pblock != heap->phead; pblock = pblock->pprev) {
        if (pblock != heap->ptail) {
            counter++;
            printf("=====================\n");
            printf("%d\n", counter);
            printf("pointer: %p\n", (void *) pblock);
            printf("free: %d\n", pblock->free);
            printf("memory: %zu\n", pblock->size);
            printf("Total Block Size: %zu\n", BLOCK_SIZE(pblock->size));
            size += pblock->size;
            total_size += BLOCK_SIZE(pblock->size);
        }
    }
    printf("=====================\n");
    printf("TOTAL MEMORY SIZE: %llu\n", size);
    printf("TOTAL BLOCKS SIZE: %llu\n", total_size);

}

size_t calculate_distance_between_pointers(struct block_t *ptr1, struct block_t *ptr2) {
    unsigned long res = (uint8_t *) ptr2 - (uint8_t *) ptr1;
    return res;
}

struct block_t *find_first_fit(size_t size) {

    for (struct block_t *pblock = heap->phead; pblock != heap->ptail; pblock = pblock->pnext) {
        if (pblock->free == 1) {
            size_t pblock_total_size = calculate_distance_between_pointers(pblock, pblock->pnext);

            if (pblock_total_size >= BLOCK_SIZE(size)) {//we split block // + BLOCK_SIZE(MINIMAL_MALLOC_MEM)
                return pblock;
            }
        }
    }
    return NULL;
}

int isThatBlockBeginning(uint8_t *pointer);

struct block_t *find_first_fit2(size_t size) {
    for (struct block_t *pblock = heap->phead; pblock != heap->ptail; pblock = pblock->pnext) {
        if (pblock->free == 1 && ((intptr_t) pblock->memory & (intptr_t) (PAGE_SIZE - 1)) == 0) {
            size_t pblock_total_size = calculate_distance_between_pointers(pblock, pblock->pnext);

            if (pblock_total_size >= BLOCK_SIZE(size)) {//we split block // + BLOCK_SIZE(MINIMAL_MALLOC_MEM)
                return pblock;
            }
        }
    }
    return NULL;
}

int isThatBlockBeginning(uint8_t *pointer) {
    for (struct block_t *pblock = heap->phead->pnext; pblock != heap->ptail; pblock = pblock->pnext) {
        if ((uint8_t *) pblock == pointer) return 1;
    }
    return 0;
}

struct block_t *split_block(struct block_t *pBlock, size_t size) {

    struct block_t *pPrev = pBlock->pprev;
    struct block_t *pNext = pBlock->pnext;
    size_t block_size = pBlock->size;

    struct block_t *rest_block = (struct block_t *) ((uint8_t *) pBlock + BLOCK_SIZE(size));
    init_block(pBlock, size, pPrev, rest_block);
    pBlock->free = 0;
    size_t memorySize = BLOCK_SIZE(block_size) - BLOCK_SIZE(size) - sizeof(struct block_t) - 2 * (FENCE_LENGTH);
    init_block(rest_block, memorySize, pBlock, pNext);
    rest_block->free = 1;
    pNext->pprev = rest_block;
    heap->headers += 1;
    pNext->control_sum = calculate_block_control_sum(pNext);
    rest_block->control_sum = calculate_block_control_sum(rest_block);


    return pBlock;
}

struct block_t *claim_more_mem_than_needed(struct block_t *pfit, size_t needed_memory);

void split_in_realloc(size_t count, struct block_t *block, size_t full_memory);

size_t calculate_needed_pages2(size_t i);

int heap_setup(void) {
    if ((heap = (struct heap_t *) custom_sbrk(PAGE_SIZE)) == (void *) -1) return -1;
    heap->headers = 3;
    heap->pages = 1;
    heap->phead = (struct block_t *) ((uint8_t *) heap + sizeof(struct heap_t));
    heap->ptail = (struct block_t *) ((uint8_t *) heap + PAGE_SIZE - sizeof(struct block_t));
    heap->pfree = (struct block_t *) ((uint8_t *) heap->phead + sizeof(struct block_t));
    heap->phead->pnext = heap->pfree;
    heap->phead->pprev = NULL;
    heap->ptail->pnext = NULL;
    heap->ptail->pprev = heap->pfree;
    heap->pfree->pnext = heap->ptail;
    heap->pfree->pprev = heap->phead;

    heap->phead->size = 0;
    heap->ptail->size = 0;
    heap->phead->free = 0;
    heap->ptail->free = 0;
    heap->pfree->free = 1;
    heap->pfree->size = (uint8_t *) heap->ptail - (uint8_t *) heap->pfree - sizeof(struct block_t) - 2 * FENCE_LENGTH;
    init_block(heap->pfree, heap->pfree->size, heap->phead, heap->ptail);
    heap->phead->control_sum = calculate_block_control_sum(heap->phead);
    heap->pfree->control_sum = calculate_block_control_sum(heap->pfree);
    heap->ptail->control_sum = calculate_block_control_sum(heap->ptail);
    heap->initialized = INITIALIZED_NUMBER;
    heap->control_sum = calculate_heap_control_sum();
    return 0;
}

struct block_t *claim_more_mem_than_needed(struct block_t *pfit, size_t needed_memory) {
    struct block_t *pPrev = pfit->pprev;
    struct block_t *pNext = pfit->pnext;

    init_block(pfit, needed_memory, pPrev, pNext);
    pfit->free = 0;

    return pfit;
}

size_t calculate_heap_control_sum() {
    size_t result = 0;
    for (uint8_t *temp = (uint8_t *) heap;
         temp != ((uint8_t *) heap + sizeof(struct heap_t) - sizeof(size_t)); temp++) {
        result += *temp;
    }
    return result;
}

size_t calculate_block_control_sum(struct block_t *block) {
    size_t result = 0;
    for (uint8_t *temp = (uint8_t *) block;
         temp != ((uint8_t *) block + sizeof(struct block_t) - sizeof(size_t)); temp++) {
        result += *temp;
    }
    return result;
}


void heap_clean(void) {
    if (heap_validate() == 2) return;
    intptr_t mem_size = heap->pages * PAGE_SIZE;
    memset(heap, 0x0, mem_size);
    custom_sbrk(-mem_size);
}

void *heap_malloc(size_t size) {
    if (heap_validate() || size < 1) return NULL;

    struct block_t *pfit = find_first_fit(size);
    size_t needed_pages;
    if (pfit == NULL) {
        needed_pages = calculate_needed_pages(BLOCK_SIZE(size));
        if (request_space(needed_pages) == -1) return NULL;
    }
    pfit = find_first_fit(size);
    struct block_t *allocated_block = NULL;
    if (pfit->size == size) {
        pfit->free = 0;
        allocated_block = pfit;
    } else if (BLOCK_SIZE(pfit->size) > BLOCK_SIZE(size) + BLOCK_SIZE(MINIMAL_MALLOC_MEM)) {
        allocated_block = split_block(pfit, size);
    } else if (BLOCK_SIZE(pfit->size) > BLOCK_SIZE(size)) {
        allocated_block = claim_more_mem_than_needed(pfit, size);

    }
    heap->control_sum = calculate_heap_control_sum();
    allocated_block->control_sum = calculate_block_control_sum(allocated_block);

    return allocated_block->memory;
}

void init_block(struct block_t *block_pos, size_t memory_size, struct block_t *prev, struct block_t *next) {
    block_pos->size = memory_size;
    block_pos->pprev = prev;
    block_pos->pnext = next;
    uint8_t *pointer = (uint8_t *) block_pos + sizeof(struct block_t);
    block_pos->memory = pointer + FENCE_LENGTH;
    for (int i = 0; i < FENCE_LENGTH; ++i) {
        *(pointer + i) = '#';
    }
    pointer = (uint8_t *) (uint8_t *) block_pos + sizeof(struct block_t) + memory_size + FENCE_LENGTH;
    for (int i = 0; i < FENCE_LENGTH; ++i) {
        *(pointer + i) = '#';
    }

}


int request_space(size_t pages) {
    if (custom_sbrk(PAGE_SIZE * pages) == (void *) -1) return -1;
    struct block_t *pprev_temp = heap->ptail->pprev;
    heap->pages += pages;
    heap->ptail = (struct block_t *) ((uint8_t *) heap + PAGE_SIZE * heap->pages - sizeof(struct block_t));
    heap->ptail->pnext = NULL;
    heap->ptail->size = 0;
    heap->ptail->free = 0;

    if (pprev_temp->free == 1) {
        struct block_t *prev_pprev_temp = pprev_temp->pprev;
        if (pprev_temp->pprev != heap->phead) {
            pprev_temp = (struct block_t *) ((uint8_t *) pprev_temp->pprev + BLOCK_SIZE(
                    pprev_temp->pprev->size));
            heap->ptail->pprev = pprev_temp;
            prev_pprev_temp->pnext = pprev_temp;
        }
        size_t size = (uint8_t *) heap->ptail - (uint8_t *) pprev_temp - sizeof(struct block_t) - 2 * FENCE_LENGTH;
        init_block(pprev_temp, size, prev_pprev_temp, heap->ptail);
        pprev_temp->free = 1;


    } else {
        struct block_t *newTail = (struct block_t *) ((uint8_t *) pprev_temp + BLOCK_SIZE(pprev_temp->size));
        init_block(newTail, (uint8_t *) heap->ptail - (uint8_t *) newTail - sizeof(struct block_t) - 2 * FENCE_LENGTH,
                   pprev_temp,
                   heap->ptail);
        newTail->free = 1;
        heap->ptail->pprev = newTail;
        pprev_temp->pnext = newTail;
        pprev_temp = newTail;
    }

    heap->ptail->pprev = pprev_temp;
    heap->ptail->pnext = NULL;


    heap->ptail->control_sum = calculate_block_control_sum(heap->ptail);
    heap->ptail->pprev->control_sum = calculate_block_control_sum(heap->ptail->pprev);
    heap->ptail->pprev->pprev->control_sum = calculate_block_control_sum(heap->ptail->pprev->pprev);
    heap->control_sum = calculate_heap_control_sum();
    return 0;
}

int request_space2(size_t pages) {
    if (custom_sbrk(PAGE_SIZE * pages) == (void *) -1) return -1;
    struct block_t *pprev_temp = heap->ptail->pprev;
    heap->pages += pages;
    heap->ptail = (struct block_t *) ((uint8_t *) heap + PAGE_SIZE * heap->pages - sizeof(struct block_t));
    heap->ptail->pnext = NULL;
    heap->ptail->size = 0;
    heap->ptail->free = 0;

    if (pprev_temp->free == 1) {
        struct block_t *prev_pprev_temp = pprev_temp->pprev;
        if (pprev_temp->pprev != heap->phead) {
            pprev_temp = (struct block_t *) ((uint8_t *) pprev_temp->pprev + BLOCK_SIZE(
                    pprev_temp->pprev->size));
            heap->ptail->pprev = pprev_temp;
            prev_pprev_temp->pnext = pprev_temp;
        }
        size_t size = (uint8_t *) heap->ptail - (uint8_t *) pprev_temp - sizeof(struct block_t) - 2 * FENCE_LENGTH;
        init_block(pprev_temp, size, prev_pprev_temp, heap->ptail);
        pprev_temp->free = 1;


    } else {
        struct block_t *newTail = (struct block_t *) ((uint8_t *) pprev_temp + BLOCK_SIZE(pprev_temp->size));
        init_block(newTail, (uint8_t *) heap->ptail - (uint8_t *) newTail - sizeof(struct block_t) - 2 * FENCE_LENGTH,
                   pprev_temp,
                   heap->ptail);
        newTail->free = 1;
        heap->ptail->pprev = newTail;
        pprev_temp->pnext = newTail;
        pprev_temp = newTail;
    }

    heap->ptail->pprev = pprev_temp;
    heap->ptail->pnext = NULL;


    heap->ptail->control_sum = calculate_block_control_sum(heap->ptail);
    heap->ptail->pprev->control_sum = calculate_block_control_sum(heap->ptail->pprev);
    heap->ptail->pprev->pprev->control_sum = calculate_block_control_sum(heap->ptail->pprev->pprev);
    heap->control_sum = calculate_heap_control_sum();
    return 0;
}


size_t calculate_needed_pages(size_t size) {
    size_t needed_pages;
    size_t needed_memory = size;
    if (heap->ptail->pprev->free == 1) {
        needed_memory -= BLOCK_SIZE(heap->ptail->pprev->size);
    }
    needed_pages = needed_memory / PAGE_SIZE + ((needed_memory % PAGE_SIZE) != 0);
    return needed_pages;
}

void *heap_calloc(size_t number, size_t size) {
    void *mem = heap_malloc(size * number);
    if (mem) memset(mem, 0, size * number);
    return mem;
}

void *heap_realloc(void *memblock, size_t count) {
    if ((!(memblock || count)) || (long long) count < 0 || heap_validate()) return NULL;
    if (!memblock) return heap_malloc(count);
    if (get_pointer_type(memblock) != pointer_valid) return NULL;
    if (count == 0) {
        heap_free(memblock);
        return NULL;
    }

    struct block_t *block = (struct block_t *) ((uint8_t *) memblock - FENCE_LENGTH - sizeof(struct block_t));
    if (count < block->size) {
        init_block(block, count, block->pprev, block->pnext);
        block->free = 0;
        block->control_sum = calculate_block_control_sum(block);
        return block->memory;
    } else if (count == block->size) {
        return block->memory;
    } else {
        if (block->pnext->free == 1 &&
            (calculate_distance_between_pointers(block, block->pnext->pnext) >= BLOCK_SIZE(count))) {
            size_t full_memory = calculate_distance_between_pointers(block, block->pnext->pnext);
            size_t available_memory = full_memory - BLOCK_SIZE(1);
            if (available_memory >= BLOCK_SIZE(count)) {
                split_in_realloc(count, block, full_memory);
                return block->memory;
            } else if (full_memory >= BLOCK_SIZE(count)) {
                struct block_t *pnext_next = block->pnext->pnext;
                init_block(block, count, block->pprev, pnext_next);
                pnext_next->pprev = block;
                block->control_sum = calculate_block_control_sum(block);
                pnext_next->control_sum = calculate_block_control_sum(pnext_next);
                return block->memory;
            }
        } else if (block == heap->ptail->pprev || (block == heap->ptail->pprev->pprev && heap->ptail->pprev->free)) {
            if (calculate_distance_between_pointers(block, heap->ptail) >=
                BLOCK_SIZE(count)) {
                init_block(block, block->size, block->pprev, heap->ptail);
                block->control_sum = calculate_block_control_sum(block);
                heap->ptail->pprev = block;
                heap->ptail->control_sum = calculate_block_control_sum(heap->ptail);

                return block->memory;
            } else {
                size_t needed_pages;
                needed_pages = calculate_needed_pages(BLOCK_SIZE(count) + BLOCK_SIZE(1));
                if (request_space(needed_pages) == -1) return NULL;
                struct block_t *before_split = block->pprev;
                struct block_t *first_block = block;
                struct block_t *second_block = (struct block_t *) ((uint8_t *) block + BLOCK_SIZE(count));
                init_block(first_block, count, before_split, second_block);
                init_block(second_block, (uint8_t *) heap->ptail - (uint8_t *) second_block - sizeof(struct block_t) -
                                         2 * FENCE_LENGTH, first_block, heap->ptail);
                second_block->free = 1;

                before_split->pnext = first_block;
                heap->ptail->pprev = second_block;
                before_split->control_sum = calculate_block_control_sum(before_split);
                first_block->control_sum = calculate_block_control_sum(first_block);
                second_block->control_sum = calculate_block_control_sum(second_block);
                heap->ptail->control_sum = calculate_block_control_sum(heap->ptail);
                return block->memory;
            }
        } else {
            void *malloc_result = heap_malloc(count);
            if (malloc_result == NULL) return NULL;
            memcpy(malloc_result, block->memory, block->size);

            heap_free(block->memory);

            return malloc_result;
        }
    }

    return NULL;
}

void split_in_realloc(size_t count, struct block_t *block, size_t full_memory) {
    struct block_t *block_after_downsized = block->pnext->pnext;
    struct block_t *block_before_enlarged = block->pprev;

    struct block_t *downsized_pos = (struct block_t *) ((uint8_t *) block + BLOCK_SIZE(count));
    init_block(block, count, block_before_enlarged, downsized_pos);
    block->free = 0;
    block->control_sum = calculate_block_control_sum(block);

    size_t memorySize = full_memory - 2 * BLOCK_SIZE(0) - count;
    init_block(downsized_pos, memorySize, block, block_after_downsized);
    downsized_pos->free = 1;
    downsized_pos->control_sum = calculate_block_control_sum(downsized_pos);

    block_after_downsized->pprev = downsized_pos;
    block_after_downsized->control_sum = calculate_block_control_sum(block_after_downsized);

    block_before_enlarged->pnext = block;
    block_before_enlarged->control_sum = calculate_block_control_sum(block_before_enlarged);

}

void heap_free(void *memblock) {
    if (!(heap_validate() != 2 && memblock && get_pointer_type(memblock) == pointer_valid)) return;
    struct block_t *pblock = (struct block_t *) ((uint8_t *) memblock - FENCE_LENGTH - sizeof(struct block_t));
    struct block_t *pNext = pblock->pnext;
    struct block_t *pPrev = pblock->pprev;

    pblock->free = 1;

    if ((uint8_t *) pNext - (uint8_t *) pblock != (long) BLOCK_SIZE(pblock->size)) {
        pblock->size += (uint8_t *) pNext - (uint8_t *) pblock - (long) BLOCK_SIZE(pblock->size);
        //
        init_block(pblock, pblock->size, pblock->pprev, pblock->pnext);
    }

    if (pPrev->free == 1 && ((intptr_t) pblock->memory & (intptr_t) (PAGE_SIZE - 1)) != 0) {
        size_t total_memory = calculate_distance_between_pointers(pPrev, pblock->pnext);
        size_t user_memory = total_memory - sizeof(struct block_t) - 2 * FENCE_LENGTH;
        init_block(pPrev, user_memory, pPrev->pprev, pNext);
        pNext->pprev = pPrev;
        pNext->control_sum = calculate_block_control_sum(pNext);


        pblock = pPrev;
        pPrev = pblock->pprev;
        pNext = pblock->pnext;
    }
    if (pblock->pnext->free == 1) {
        size_t total_memory = calculate_distance_between_pointers(pblock, pNext->pnext);
        size_t user_memory = total_memory - sizeof(struct block_t) - 2 * FENCE_LENGTH;
        struct block_t *pNextNext = pNext->pnext;
        init_block(pblock, user_memory, pPrev, pNextNext);
        pNextNext->pprev = pblock;
        pNextNext->control_sum = calculate_block_control_sum(pNextNext);
    }
    heap->control_sum = calculate_heap_control_sum();
    pblock->control_sum = calculate_block_control_sum(pblock);

}

size_t heap_get_largest_used_block_size(void) {
    if (heap_validate() != 0) return 0;
    if (heap->headers == 3 && heap->pfree->free == 1) return 0;

    struct block_t *largest_block = NULL;
    for (struct block_t *pblock = heap->phead; pblock != heap->ptail; pblock = pblock->pnext) {
        if (pblock != heap->phead && pblock->free == 0) {
            if (largest_block == NULL) largest_block = pblock;
            if (pblock->size > largest_block->size) largest_block = pblock;
        }
    }
    if (largest_block == NULL) return 0;
    return largest_block->size;
}

enum pointer_type_t get_pointer_type(const void *const pointer) {
    if (!pointer) return pointer_null;
    if (heap_validate() == 1) return pointer_heap_corrupted;


    if ((uint8_t *) pointer < (uint8_t *) heap) return pointer_unallocated;
    if ((uint8_t *) pointer < (uint8_t *) ((uint8_t *) heap + sizeof(struct heap_t))) return pointer_control_block;
    if ((uint8_t *) pointer > (uint8_t *) heap->ptail + sizeof(struct block_t)) return pointer_unallocated;

    for (struct block_t *pblock = heap->phead; pblock != heap->ptail; pblock = pblock->pnext) {
        if (pblock == heap->phead && (uint8_t *) pointer <= (uint8_t *) pblock + sizeof(struct block_t))
            return pointer_control_block;
        if (pblock == heap->ptail && (uint8_t *) pointer >= (uint8_t *) pblock) return pointer_control_block;
        if (pblock == heap->phead) continue;


        uint8_t *unallocated_before_block = (uint8_t *) pblock;
        uint8_t *block = (uint8_t *) pblock + sizeof(struct block_t);
        uint8_t *left_fence = (uint8_t *) pblock + FENCE_LENGTH + sizeof(struct block_t);
        uint8_t *memory = (uint8_t *) pblock->memory + pblock->size;
        uint8_t *right_fence = memory + FENCE_LENGTH;

        if ((uint8_t *) pointer < unallocated_before_block) return pointer_unallocated;
        else if ((uint8_t *) pointer < block) return pointer_control_block;
        else if ((uint8_t *) pointer < left_fence && !pblock->free) return pointer_inside_fences;
        else if ((uint8_t *) pointer < left_fence) return pointer_unallocated;
        else if ((uint8_t *) pointer == (uint8_t *) (pblock)->memory && !pblock->free) return pointer_valid;
        else if ((uint8_t *) pointer == (uint8_t *) (pblock)->memory) return pointer_unallocated;
        else if ((uint8_t *) pointer < memory && !pblock->free) return pointer_inside_data_block;
        else if ((uint8_t *) pointer < memory) return pointer_unallocated;
        else if ((uint8_t *) pointer < right_fence && !pblock->free) return pointer_inside_fences;
        else if ((uint8_t *) pointer < right_fence) return pointer_unallocated;
    }

    return pointer_unallocated;
}

int check_fences() {
    for (struct block_t *block_pos = heap->phead; block_pos != heap->ptail; block_pos = block_pos->pnext) {
        if (block_pos == heap->phead) continue;

        uint8_t *pointer = (uint8_t *) block_pos + sizeof(struct block_t);
        for (int i = 0; i < FENCE_LENGTH; ++i) {
            if (*(pointer + i) != '#') {
                return 1;
            }
        }
        pointer = (uint8_t *) (uint8_t *) block_pos + sizeof(struct block_t) + block_pos->size + FENCE_LENGTH;
        for (int i = 0; i < FENCE_LENGTH; ++i) {
            if (*(pointer + i) != '#') {

                return 1;
            }
        }
    }
    return 0;
}

int heap_validate(void) {
    if (heap == NULL || heap->initialized != INITIALIZED_NUMBER) return 2;
    if (calculate_heap_control_sum() != heap->control_sum) return 3;
    for (struct block_t *temp = heap->phead; temp != heap->ptail->pnext; temp = temp->pnext) {
        size_t controlSum = calculate_block_control_sum(temp);
        if (temp->control_sum != controlSum) {
            return 3;
        }
    }
    if (check_fences() == 1) return 1;
    return 0;
}

void *heap_malloc_aligned(size_t count) {
    if (heap_validate() || count < 1) return NULL;

    struct block_t *pfit = find_first_fit2(count);
    size_t needed_pages;
    if (pfit == NULL) {
        needed_pages = calculate_needed_pages2(BLOCK_SIZE(count));
        if (request_space2(needed_pages) == -1) return NULL;

        struct block_t * prev_temp = heap->ptail->pprev;
        uint8_t * nextPagePointer = getNextPagePointer((uint8_t *)prev_temp);
        size_t distance = calculate_distance_between_pointers(prev_temp, (struct block_t *)nextPagePointer);
        if (distance < sizeof(struct block_t) + FENCE_LENGTH) {
            nextPagePointer = getNextPagePointer(nextPagePointer + 1);
            distance = calculate_distance_between_pointers(prev_temp, (struct block_t *)nextPagePointer);
        }
        while (nextPagePointer > (uint8_t *)heap->ptail) request_space2(1);
        struct block_t* result = NULL;
        if (distance >= BLOCK_SIZE(MINIMAL_MALLOC_MEM) + sizeof(struct block_t) + FENCE_LENGTH) {
            struct block_t * before_aligned = split_block(prev_temp, distance - sizeof(struct block_t) - FENCE_LENGTH - FENCE_LENGTH - sizeof(struct block_t) - FENCE_LENGTH);
            before_aligned->free = 1;
            struct block_t * aligned = before_aligned->pnext;
            result = aligned;
        }else{
            struct block_t * pprev_prev_temp = prev_temp->pprev;
            struct block_t * newBlockPos = (struct block_t *) (nextPagePointer - sizeof(struct block_t) - FENCE_LENGTH);
            init_block(newBlockPos, calculate_distance_between_pointers((struct block_t *)newBlockPos,heap->ptail) -
                    BLOCK_SIZE(0),pprev_prev_temp,heap->ptail);
            pprev_prev_temp->pnext = newBlockPos;
            heap->ptail->pprev = newBlockPos;
            result = newBlockPos;
        }
        result->free = 0;
        if (BLOCK_SIZE(result->size) >= BLOCK_SIZE(count) + BLOCK_SIZE(MINIMAL_MALLOC_MEM)) {
            result = split_block(result, count);
        }else result = claim_more_mem_than_needed(result, count);
        heap->control_sum = calculate_heap_control_sum();
        result->pprev->control_sum = calculate_block_control_sum(result->pprev);
        result->control_sum = calculate_block_control_sum(result);
        result->pnext->control_sum = calculate_block_control_sum(result->pnext);

        return result->memory;
    }

    pfit = find_first_fit2(count);
    struct block_t *allocated_block = NULL;
    if (pfit->size == count ) {
        pfit->free = 0;
        allocated_block = pfit;
    } else if (BLOCK_SIZE(pfit->size) > BLOCK_SIZE(count) + BLOCK_SIZE(MINIMAL_MALLOC_MEM)) {
        allocated_block = split_block(pfit, count);

    } else if (BLOCK_SIZE(pfit->size) > BLOCK_SIZE(count)) {
        allocated_block = claim_more_mem_than_needed(pfit, count);

    }

    heap->control_sum = calculate_heap_control_sum();
    allocated_block->pprev->control_sum = calculate_block_control_sum(allocated_block->pprev);
    allocated_block->control_sum = calculate_block_control_sum(allocated_block);
    allocated_block->pnext->control_sum = calculate_block_control_sum(allocated_block->pnext);

    return allocated_block->memory;
}

size_t calculate_needed_pages2(size_t size) {
    size_t needed_pages;
    size_t needed_memory = size;

    needed_pages = needed_memory / PAGE_SIZE + ((needed_memory % PAGE_SIZE) != 0);
    return needed_pages + 1;
}

void *heap_calloc_aligned(size_t number, size_t size) {
    void *mem = heap_malloc_aligned(size * number);
    if (mem) memset(mem, 0, size * number);
    return mem;
}

void *heap_realloc_aligned(void *memblock, size_t size) {
    if ((!(memblock || size)) || (long long) size < 0 || heap_validate()) return NULL;
    if (!memblock) return heap_malloc_aligned(size);
    if (get_pointer_type(memblock) != pointer_valid) return NULL;
    if (size == 0) {
        heap_free(memblock);
        return NULL;
    }

    struct block_t *block = (struct block_t *) ((uint8_t *) memblock - FENCE_LENGTH - sizeof(struct block_t));
    if (size < block->size) {
        init_block(block, size, block->pprev, block->pnext);
        block->free = 0;
        block->control_sum = calculate_block_control_sum(block);
        return block->memory;
    } else if (size == block->size) {
        return block->memory;
    } else {
        if (block->pnext->free == 1 &&
            (calculate_distance_between_pointers(block, block->pnext->pnext) >= BLOCK_SIZE(size))) {
            size_t full_memory = calculate_distance_between_pointers(block, block->pnext->pnext);
            size_t available_memory = full_memory - BLOCK_SIZE(1);
            if (available_memory >= BLOCK_SIZE(size)) {
                split_in_realloc(size, block, full_memory);

                return block->memory;
            } else if (full_memory >= BLOCK_SIZE(size)) {
                struct block_t *pnext_next = block->pnext->pnext;
                init_block(block, size, block->pprev, pnext_next);
                pnext_next->pprev = block;
                block->control_sum = calculate_block_control_sum(block);
                pnext_next->control_sum = calculate_block_control_sum(pnext_next);

                return block->memory;
            }
        } else if (block == heap->ptail->pprev || (block == heap->ptail->pprev->pprev && heap->ptail->pprev->free)) {
            if (calculate_distance_between_pointers(block, heap->ptail) >=
                BLOCK_SIZE(size)) {
                init_block(block, block->size, block->pprev, heap->ptail);
                block->control_sum = calculate_block_control_sum(block);
                heap->ptail->pprev = block;
                heap->ptail->control_sum = calculate_block_control_sum(heap->ptail);

                return block->memory;
            } else {
                size_t needed_pages;
                needed_pages = calculate_needed_pages(BLOCK_SIZE(size) + BLOCK_SIZE(1));
                if (request_space(needed_pages) == -1) return NULL;
                struct block_t *before_split = block->pprev;
                struct block_t *first_block = block;
                struct block_t *second_block = (struct block_t *) ((uint8_t *) block + BLOCK_SIZE(size));
                init_block(first_block, size, before_split, second_block);
                init_block(second_block, (uint8_t *) heap->ptail - (uint8_t *) second_block - sizeof(struct block_t) -
                                         2 * FENCE_LENGTH, first_block, heap->ptail);
                second_block->free = 1;

                before_split->pnext = first_block;
                heap->ptail->pprev = second_block;
                before_split->control_sum = calculate_block_control_sum(before_split);
                first_block->control_sum = calculate_block_control_sum(first_block);
                second_block->control_sum = calculate_block_control_sum(second_block);
                heap->ptail->control_sum = calculate_block_control_sum(heap->ptail);
                return block->memory;
            }
        } else {
            bool condition1 = block->pprev && block->pprev->pprev && block->pprev->pprev->pprev && block->pprev->pprev->pprev && block->pprev->pprev->pprev->pprev &&
                    block->pprev->pprev->pprev->pprev == heap->phead && block->pprev->pprev->pprev->free == 1 && block->pprev->pprev->free == 0 && block->pprev->free == 1 && block->pnext && block->pnext->pnext && block->pnext->pnext->pnext && block->pnext->free &&
                    block->pnext->pnext->free;
            if (condition1 && ((intptr_t) block->memory & (intptr_t) (PAGE_SIZE - 1)) == 0 && (BLOCK_SIZE(block->size) + BLOCK_SIZE(block->pnext->size) + BLOCK_SIZE(block->pnext->size) +
                                                                                               BLOCK_SIZE(block->pnext->pnext->size)) > BLOCK_SIZE(size)) {
                struct block_t * temp_pprev = block->pprev;
                struct block_t * after = block->pnext->pnext->pnext;
                struct block_t * newBlock = block;
                init_block(newBlock, calculate_distance_between_pointers(newBlock,block->pnext->pnext->pnext),temp_pprev,after);
                after->pprev = newBlock;
                temp_pprev->pnext = newBlock;
                newBlock->free = 0;

                if (BLOCK_SIZE(newBlock->size) > BLOCK_SIZE(size) + BLOCK_SIZE(MINIMAL_MALLOC_MEM)) {
                    split_block(newBlock, size);
                }else{
                    claim_more_mem_than_needed(newBlock,size);
                }

                for (struct block_t *pblock = heap->phead; pblock != heap->ptail->pnext; pblock = pblock->pnext) { 
                    pblock->control_sum = calculate_block_control_sum(pblock);
                }

                heap->control_sum = calculate_heap_control_sum();
                return newBlock->memory;

            }else{
            void *malloc_result = heap_malloc_aligned(size);
            if (malloc_result == NULL) return NULL;
            memcpy(malloc_result, block->memory, block->size);
            heap_free(block->memory);

            return malloc_result;}
        }
    }

    return NULL;
}

