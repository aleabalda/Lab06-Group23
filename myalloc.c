#include <stddef.h>
#include <sys/mman.h>
#include "myalloc.h"

static node_t *_arena_start = NULL;

int statusno = 0;

int myinit(size_t size)
{
    size_t _arena_size = size;
    size_t free_space = size;

    if (_arena_start != NULL)
    {
        statusno = ERR_CALL_FAILED;
        return statusno;
    }

    if (size > MAX_ARENA_SIZE || size <= 0)
    {
        statusno = ERR_BAD_ARGUMENTS;
        return statusno;
    }

    printf("Initializing arena:\n");

    size_t adjusted_size = size;
    if (adjusted_size % getpagesize() != 0)
    {
        // Adjust the size to the nearest page boundary
        adjusted_size += getpagesize() - (adjusted_size % getpagesize());
    }

    printf("...requested size %zu bytes\n", size);
    printf("...pagesize is %d bytes\n", getpagesize());
    printf("...adjusting size with page boundaries\n");
    printf("...adjusted size is %zu bytes\n", adjusted_size);
    printf("...mapping arena with mmap()\n");
    printf("...arena starts at %p\n", _arena_start);
    printf("...arena ends at %p\n", (char *)_arena_start + adjusted_size);
}

int mydestroy()
{
    if (_arena_start == NULL)
    {
        statusno = ERR_UNINITIALIZED;
        return statusno;
    }

    if (munmap(_arena_start, _arena_start->size + sizeof(node_t)) != 0)
    {
        statusno = ERR_SYSCALL_FAILED;
        return statusno;
    }

    _arena_start = NULL;
    statusno = 0;
    return statusno;
}

void *myalloc(size_t size)
{
    if (_arena_start == NULL)
    {
        statusno = ERR_UNINITIALIZED;
        return NULL;
    }

    size_t adjusted_size = ((size + sizeof(node_t) - 1) / sizeof(node_t)) * sizeof(node_t);
    node_t *current = _arena_start;

    while (current != NULL)
    {
        if (current->is_free && current->size >= adjusted_size)
        {
            if (current->size > adjusted_size + sizeof(node_t))
            {
                node_t *split_block = (node_t *)((char *)current + adjusted_size);
                split_block->size = current->size - adjusted_size - sizeof(node_t);
                split_block->is_free = 1;
                split_block->fwd = current->fwd;
                split_block->bwd = current;
                current->size = adjusted_size;
                current->fwd = split_block;

                if (split_block->fwd != NULL)
                {
                    split_block->fwd->bwd = split_block;
                }
            }

            current->is_free = 0;
            statusno = 0;
            return (void *)((char *)current + sizeof(node_t));
        }
        current = current->fwd;
    }

    statusno = ERR_OUT_OF_MEMORY;
    return NULL;
}

void myfree(void *ptr)
{
    if (_arena_start == NULL)
    {
        statusno = ERR_UNINITIALIZED;
        return;
    }

    node_t *block = (node_t *)((char *)ptr - sizeof(node_t));
    block->is_free = 1;

    if (block->fwd != NULL && block->fwd->is_free)
    {
        block->size += block->fwd->size + sizeof(node_t);
        block->fwd = block->fwd->fwd;

        if (block->fwd != NULL)
        {
            block->fwd->bwd = block;
        }
    }

    if (block->bwd != NULL && block->bwd->is_free)
    {
        block->bwd->size += block->size + sizeof(node_t);
        block->bwd->fwd = block->fwd;

        if (block->fwd != NULL)
        {
            block->fwd->bwd = block->bwd;
        }
    }

    statusno = 0;
}
