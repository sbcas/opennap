/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

typedef struct mempool
{
    unsigned int count;		/* number of allocated chunks */
    unsigned int *mask;		/* bitmask of free/used blocks */
    char **data;		/* chunks of data */
    int blocksize;		/* size of data block */
}
MEMPOOL;

MEMPOOL *mp_init (int);
void *mp_alloc (MEMPOOL *, int);
void mp_free (MEMPOOL *, void *);
void mp_cleanup (MEMPOOL *);
