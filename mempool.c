/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdlib.h>
#include "mempool.h"
#include "debug.h"

/* routines to implement a memory pool.  useful when a program needs to
   allocate and free many structures of the same size. */

/* number of blocks in a chunk */
#define BITS sizeof(int)*8

MEMPOOL *
mp_init (int blocksize)
{
    MEMPOOL *mem = CALLOC (1, sizeof (MEMPOOL));

    ASSERT (blocksize != 0);
    mem->blocksize = blocksize;
    return mem;
}

void *
mp_alloc (MEMPOOL * mem, int clr)
{
    unsigned int n, j;

    for (n = 0; n < mem->count; n++)
    {
	/* skip chunks we know are full */
	if (mem->mask[n] != ~0U)
	{
	    /* look for a free block in this chunk */
	    for (j = 0; j < BITS; j++)
		if ((mem->mask[n] & (1 << j)) == 0)
		{
		    mem->mask[n] |= 1 << j;
		    if (clr)
			memset (mem->data[n] + mem->blocksize * j, 0,
				mem->blocksize);
		    return (mem->data[n] + mem->blocksize * j);
		}
	}
    }
    /* need to allocate a new chunk */
    mem->count++;
    mem->mask = REALLOC (mem->mask, sizeof (int) * (mem->count));
    mem->mask[n] = 1;
    mem->data = REALLOC (mem->data, sizeof (char *) * (mem->count));
    mem->data[n] = MALLOC (mem->blocksize * BITS); /* allocate chunk */
    if (clr)
	memset (mem->data[n], 0, mem->blocksize);
    return (mem->data[n]); /* return first block */
}

void
mp_free (MEMPOOL * mem, void *ptr)
{
    unsigned int n;

    for (n = 0; n < mem->count; n++)
    {
	if ((char *) ptr >= mem->data[n]
	    && (char *) ptr < mem->data[n] + mem->blocksize * BITS)
	{
	    /* mark as unused */
	    mem->mask[n] &=
		~(1 << (((char *) ptr - mem->data[n]) / mem->blocksize));
	    return;
	}
    }
    /* should not get here.  this only happens when `ptr' was not allocated
       as part of this memory pool */
    ASSERT (0);
}

void
mp_cleanup (MEMPOOL * mem)
{
    unsigned int n;

    ASSERT (mem != 0);
    if (mem->count > 0)
    {
	for (n = 0; n < mem->count; n++)
	    FREE (mem->data[n]);
	FREE (mem->mask);
    }
    FREE (mem);
}
