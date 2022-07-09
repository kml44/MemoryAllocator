#include <stdio.h>
#include <stdlib.h>
#include "heap.h"
#include <locale.h>
#include <assert.h>
void UTEST1(void)
{
    int status = heap_setup();
    assert(status == 0);

    size_t mem_sizes[] = {151, 444, 663, 322, 169, 260, 373, 232, 772, 618, 161, 143, 662, 597, 464, 347, 234, 956, 935, 561, 876, 362, 894, 224, 315, 647};
    void *ptrs[26];

    for (int i = 0; i < 26; ++i)
    {
        ptrs[i] = heap_malloc(mem_sizes[i]);
        assert(ptrs[i] != NULL);
        assert(pointer_valid == get_pointer_type(ptrs[i]));

        status = heap_validate();
        assert(status == 0);
    }

    heap_free(ptrs[14]);

    assert(pointer_unallocated == get_pointer_type(ptrs[14]));

    status = heap_validate();
    assert(status == 0);

    void *ptr = heap_malloc(464);
    assert(ptrs[14] == ptr);

    status = heap_validate();
    assert(status == 0);

    heap_clean();
}

void UTEST2(void)
{
    int status = heap_setup();
    assert(status == 0);

    char *ptr = heap_calloc(915, 32);

    assert(ptr != NULL);
    assert(pointer_valid == get_pointer_type(ptr));

    for (int i = 0; i < 29280; ++i)
        assert(ptr[i] == 0);

    status = heap_validate();
    assert(status == 0);

    heap_clean();
}

int main()
{
    UTEST1();
    UTEST2();
    return 0;
}
