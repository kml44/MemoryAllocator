# MemoryAllocator
The main goal of the project was to implement a reflection of the standard allocator from the stdlib.h library. Allocator do not use sbrk function but custom version of it.
##Running
When working with the allocator, do not use standard functions to perform operations on heap.
To compile run:
`gcc -pthread heap.c memmanager.c main.c`

Then:
`./a.out`

# Features
API provides four main functions and a few extra ones.
```c
void* heap_malloc(size_t size);
void* heap_calloc(size_t number, size_t size);
void* heap_realloc(void* memblock, size_t count);
void  heap_free(void* memblock);
```
# API
| function  | description  |
| ------------ | ------------ |
| int heap_setup(void);  | Initializes the internal allocator structures. Returns **0** if heap was initialized properly or **-1** if there was a problem during this process.|
| void heap_clean(void); | Returns all allocated memory to operating system and clears all the heap control structures.|
|  void* heap_malloc(size_t size); |  Allocates memory and returns a pointer to it. **Size** defines amount of memory that user want to allocate. |
|  void* heap_calloc(size_t number, size_t size); | Allocates memory and returns a pointer to it. **Number** is the number of items to allocate. **Size** defines amount of memory that user want to allocate.  |
|  void* heap_realloc(void* memblock, size_t count); | This function changes the size of memory block given by **memblock**. In case of failure function returns **NULL** |
| void  heap_free(void* memblock); | Frees up the memory block given by **memblock** pointer.  |

heap_malloc, heap_calloc and heap_realloc have also *_aligned versions that forces to allocate memory only on the beginning of the pages.
