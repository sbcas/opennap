/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

/* This is a very simple memory management debugger.  It's useful for detecting
   memory leaks, references to uninitialzed memory, bad pointers, buffer
   overflow and getting an idea of how much memory is used by a program. */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "debug.h"

#ifdef DEBUG

#define MIN(a,b) ((a<b)?a:b)

/* tunable parameter.  if you have a large amount of memory allocated, setting
   this value higher will result in faster validation of pointers */
#define SIZE 4099

typedef struct _block
{
    void *val;
    int len;
    char *file;
    int line;
    struct _block *next;
    struct _block *prev;
}
BLOCK;

static BLOCK *Allocation[SIZE];
static int Memory_Usage = 0;

void
debug_init (void)
{
    memset (Allocation, 0, sizeof (Allocation));
}

#if SIZEOF_LONG == 8
#define SHIFT 3
#else
#define SHIFT 2
#endif

/* hash the pointer value for insertion into the table */
static int
debug_hash (void *ptr)
{
    int hash;

    /* pointers are allocated on either 4 or 8 bytes boundaries, so we want
       to ignore those values.  this will cause consecutive pointers to hash
       to the next bin */
    hash = ((unsigned long) ptr) >> SHIFT;
    return ((hash & 0x7fffffff) % SIZE);
}

static int
debug_overflow (BLOCK *block, const char *func)
{
    if (*((unsigned char *) block->val + block->len) != END_BYTE)
    {
	fprintf (stderr,
		"debug_%s: buffer overflow detected in data allocated at %s:%d\n",
		func, block->file, block->line);
	return 1;
    }
    return 0;
}

static void
debug_exhausted (const char *file, int line)
{
    fprintf (stderr, "debug_malloc(): memory exhausted at %s:%d (%d bytes allocated)\n",
	    file, line, Memory_Usage);
}

void *
debug_malloc (int bytes, const char *file, int line)
{
    BLOCK *block;
    int offset;

    if (bytes == 0)
    {
	fprintf (stderr, "debug_malloc(): 0 bytes requested at %s:%d\n",
		 file, line);
	return 0;
    }

    block = malloc (sizeof (BLOCK));
    if (!block)
    {
	debug_exhausted (file, line);
	return 0;
    }
    block->val = malloc (bytes + 1);
    if (!block->val)
    {
	debug_exhausted (__FILE__, __LINE__);
	free (block);
	return 0;
    }
    Memory_Usage += bytes;
    block->len = bytes;
    block->file = strdup (file);
    if (!block->file)
    {
	debug_exhausted (__FILE__, __LINE__);
	free (block);
	free (block->val);
	return 0;
    }
    block->line = line;
    memset (block->val, ALLOC_BYTE, bytes);
    *((unsigned char *) block->val + bytes) = END_BYTE;

    offset = debug_hash (block->val);
    if (!Allocation[offset])
    {
	block->next = 0;
	block->prev = 0;
	Allocation[offset] = block;
    }
    else
    {
	if (block->val > Allocation[offset]->val)
	{
	    while (block->val > Allocation[offset]->val)
	    {
		if (!Allocation[offset]->next)
		{
		    /* insert after the current block */
		    Allocation[offset]->next = block;
		    block->prev = Allocation[offset];
		    block->next = 0;
		    return block->val;
		}
		Allocation[offset] = Allocation[offset]->next;
	    }
	    /* insert before current block */
	    block->next = Allocation[offset];
	    block->prev = Allocation[offset]->prev;
	    Allocation[offset]->prev = block;
	    if (block->prev)
		block->prev->next = block;
	}
	else			/* block->val < Allocation->val */
	{
	    while (block->val < Allocation[offset]->val)
	    {
		if (!Allocation[offset]->prev)
		{
		    /* insert before current block */
		    Allocation[offset]->prev = block;
		    block->next = Allocation[offset];
		    block->prev = 0;
		    return block->val;
		}
		Allocation[offset] = Allocation[offset]->prev;
	    }
	    /* insert after the current block */
	    block->prev = Allocation[offset];
	    block->next = Allocation[offset]->next;
	    Allocation[offset]->next = block;
	    if (block->next)
		block->next->prev = block;
	}
    }
    return block->val;
}

void *
debug_calloc (int count, int bytes, const char *file, int line)
{
    void *ptr = debug_malloc (count * bytes, file, line);
    if (!ptr)
	return 0;
    memset (ptr, 0, count * bytes);
    return ptr;
}

static BLOCK *
find_block (void *ptr)
{
    int offset = debug_hash (ptr);

    if (ptr > Allocation[offset]->val)
    {
	while (ptr > Allocation[offset]->val && Allocation[offset]->next)
	    Allocation[offset] = Allocation[offset]->next;
    }
    else
    {
	while (ptr < Allocation[offset]->val && Allocation[offset]->prev)
	    Allocation[offset] = Allocation[offset]->prev;
    }
    return (Allocation[offset]->val == ptr ? Allocation[offset] : NULL);
}

void *
debug_realloc (void *ptr, int bytes, const char *file, int line)
{
    void *newptr;
    BLOCK *block = 0;

    if (bytes == 0)
    {
	debug_free (ptr, file, line);
	return 0;
    }
    if (ptr)
    {
	block = find_block (ptr);
	if (!block)
	{
	    fprintf (stderr,
		     "debug_realloc(): invalid pointer at %s:%d\n", file,
		     line);
	    return 0;
	}
	debug_overflow (block, "realloc");
    }
    newptr = debug_malloc (bytes, file, line);
    if (!newptr)
	return 0;
    if (ptr)
    {
	memcpy (newptr, ptr, MIN (bytes, block->len));
	debug_free (ptr, file, line);
    }
    return newptr;
}

void
debug_free (void *ptr, const char *file, int line)
{
    BLOCK *block = 0;
    int offset;

    if (!ptr)
    {
	fprintf (stderr,
		 "debug_free: attempt to free NULL pointer at %s:%d\n",
		 file, line);
	return;
    }
    offset = debug_hash (ptr);
    if (!Allocation[offset])
    {
	fprintf (stderr,
		 "debug_free: attempt to free bogus pointer at %s:%d\n",
		 file, line);
	return;
    }
    /* this sets Allocation[offset] to point at the block we requested */
    find_block (ptr);
    if (Allocation[offset]->val != ptr)
    {
	fprintf (stderr,
		 "debug_free: attempt to free bogus pointer at %s:%d\n",
		 file, line);
	return;
    }
    debug_overflow (Allocation[offset], "free");
    memset (Allocation[offset]->val, FREE_BYTE, Allocation[offset]->len);
    free (Allocation[offset]->val);
    free (Allocation[offset]->file);
    Memory_Usage -= Allocation[offset]->len;

    /* remove current block from allocation list */
    if (Allocation[offset]->next)
    {
	block = Allocation[offset]->next;
	Allocation[offset]->next->prev = Allocation[offset]->prev;
    }

    if (Allocation[offset]->prev)
    {
	block = Allocation[offset]->prev;
	Allocation[offset]->prev->next = Allocation[offset]->next;
    }

    free (Allocation[offset]);
    Allocation[offset] = block;
}

void
debug_cleanup (void)
{
    int i;
    BLOCK *block;

    for (i = 0; i < SIZE; i++)
    {
	if (Allocation[i])
	{
	    block = Allocation[i];
	    while (block->prev)
		block = block->prev;
	    for (; block; block = block->next)
	    {
		fprintf (stderr, "debug_cleanup: %d bytes allocated at %s:%d\n",
			block->len, block->file, block->line);
		debug_overflow (block, "cleanup");
	    }
	}
    }
    if (Memory_Usage)
	fprintf (stderr, "debug_cleanup: %d bytes total\n", Memory_Usage);
}

char *
debug_strdup (const char *s, const char *file, int line)
{
    char *r;

    r = debug_malloc (strlen (s) + 1, file, line);
    if (!r)
	return 0;
    strcpy (r, s);
    return r;
}

/* check to see if a pointer is valid */
int
debug_valid (void *ptr, int len)
{
    BLOCK * block = find_block (ptr);

    if (!block)
    {
	fprintf (stderr, "debug_valid: invalid pointer\n");
	return 0; /* not found */
    }
    if (debug_overflow (block, "valid"))
	return 0;
    /* ensure that there are at least `len' bytes available */
    return ((len <= block->len));
}

int
debug_usage (void)
{
    return Memory_Usage;
}
#endif /* DEBUG */
