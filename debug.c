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

static BLOCK *Allocation = 0;
static int Memory_Usage = 0;

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

void *
debug_malloc (int bytes, const char *file, int line)
{
    BLOCK *block;

    if (bytes == 0)
    {
	fprintf (stderr, "debug_malloc(): 0 bytes requested at %s:%d\n",
		 file, line);
	return 0;
    }

    block = malloc (sizeof (BLOCK));
    if (!block)
    {
	fprintf (stderr, "debug_malloc(): memory exhausted at %s:%d\n",
		 file, line);
	return 0;
    }
    block->val = malloc (bytes + 1);
    if (!block->val)
    {
	fprintf (stderr, "debug_malloc(): memory exhausted at %s:%d", __FILE__,
		__LINE__);
	free (block);
	return 0;
    }
    Memory_Usage += bytes;
    block->len = bytes;
    block->file = strdup (file);
    block->line = line;
    memset (block->val, ALLOC_BYTE, bytes);
    *((unsigned char *) block->val + bytes) = END_BYTE;

    if (!Allocation)
    {
	Allocation = block;
	block->next = 0;
	block->prev = 0;
    }
    else
    {
	if (block->val > Allocation->val)
	{
	    while (block->val > Allocation->val)
	    {
		if (!Allocation->next)
		{
		    /* insert after the current block */
		    Allocation->next = block;
		    block->prev = Allocation;
		    block->next = 0;
		    return block->val;
		}
		Allocation = Allocation->next;
	    }
	    /* insert before current block */
	    block->next = Allocation;
	    block->prev = Allocation->prev;
	    Allocation->prev = block;
	    if (block->prev)
		block->prev->next = block;
	}
	else			/* block->val < Allocation->val */
	{
	    while (block->val < Allocation->val)
	    {
		if (!Allocation->prev)
		{
		    /* insert before current block */
		    Allocation->prev = block;
		    block->next = Allocation;
		    block->prev = 0;
		    return block->val;
		}
		Allocation = Allocation->prev;
	    }
	    /* insert after the current block */
	    block->prev = Allocation;
	    block->next = Allocation->next;
	    Allocation->next = block;
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
    memset (ptr, 0, count * bytes);
    return ptr;
}

static BLOCK *
find_block (void *ptr)
{
    if (ptr > Allocation->val)
    {
	while (ptr > Allocation->val && Allocation->next)
	    Allocation = Allocation->next;
    }
    else
    {
	while (ptr < Allocation->val && Allocation->prev)
	    Allocation = Allocation->prev;
    }
    return (Allocation->val == ptr ? Allocation : NULL);
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

    if (!ptr)
    {
	fprintf (stderr,
		 "debug_free: attempt to free NULL pointer at %s:%d\n",
		 file, line);
	return;
    }
    if (!Allocation)
    {
	fprintf (stderr,
		 "debug_free: free called with no memory allocated\n");
	return;
    }
    find_block (ptr);
    if (Allocation->val != ptr)
    {
	fprintf (stderr,
		 "debug_free: attempt to free bogus pointer at %s:%d\n",
		 file, line);
	return;
    }
    debug_overflow (Allocation, "free");
    memset (Allocation->val, FREE_BYTE, Allocation->len);
    free (Allocation->val);
    free (Allocation->file);
    Memory_Usage -= Allocation->len;

    /* remove current block from allocation list */
    if (Allocation->next)
    {
	block = Allocation->next;
	Allocation->next->prev = Allocation->prev;
    }

    if (Allocation->prev)
    {
	block = Allocation->prev;
	Allocation->prev->next = Allocation->next;
    }

    free (Allocation);
    Allocation = block;
}

void
debug_cleanup (void)
{
    BLOCK *block = Allocation;

    if (!Allocation)
	return;
    while (block->prev)
	block = block->prev;
    for (; block; block = block->next)
    {
	fprintf (stderr, "debug_cleanup: %d bytes allocated at %s:%d\n",
		 block->len, block->file, block->line);
	debug_overflow (block, "cleanup");
    }
}

char *
debug_strdup (const char *s, const char *file, int line)
{
    char *r;

    r = debug_malloc (strlen (s) + 1, file, line);
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

#endif /* DEBUG */
