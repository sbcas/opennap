/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software disributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "hash.h"
#include "debug.h"
#ifdef WIN32
// this is needed for the WIN32 port #def's
#include "opennap.h"
#endif

/* a simple hash table.  keys are case insensitive for this application */

/* initialize a hash table.  `buckets' should be a prime number for maximum
   dispersion of entries into buckets */
HASH *
hash_init (int buckets, hash_destroy f)
{
    HASH *h = CALLOC (1, sizeof (HASH));

    if (!h)
	return 0;
    h->numbuckets = buckets;
    if ((h->bucket = CALLOC (buckets, sizeof (HASHENT *))) == 0)
    {
	FREE (h);
	return 0;
    }
    h->destroy = f;
    return h;
}

static unsigned int
hash_string (HASH * table, const char *key)
{
    unsigned int sum = 0;

    ASSERT (key != 0);
    for (; *key; key++)
    {
	/* shifting by 1 bit prevents abc from having the same hash as acb */
	sum<<=1;
	sum += tolower (*key);
    }
    sum = sum % table->numbuckets;
    return sum;
}

int
hash_add (HASH * table, const char *key, void *data)
{
    HASHENT *he = CALLOC (1, sizeof (HASHENT));
    unsigned int sum;

    if (!he)
	return -1;
    ASSERT (key != 0);
    ASSERT (data  != 0);
    ASSERT (table != 0);
    he->key = key;
    he->data = data;
    sum = hash_string (table, key);
    he->next = table->bucket[sum];
    table->bucket[sum] = he;
    table->dbsize++;
    return 0;
}

void *
hash_lookup (HASH * table, const char *key)
{
    HASHENT *he;
    unsigned int sum = hash_string (table, key);
    he = table->bucket[sum];

    for (; he; he = he->next)
    {
	if (strcasecmp (key, he->key) == 0)
	    return he->data;
    }
    return 0;
}

int
hash_remove (HASH * table, const char *key)
{
    HASHENT **he, *ptr;
    unsigned int sum;
    
    ASSERT (table != 0);
    ASSERT (key != 0);
    sum = hash_string (table, key);
    for (he = &table->bucket[sum]; *he; he = &(*he)->next)
    {
	if (!strcasecmp (key, (*he)->key))
	{
	    ptr = (*he)->next;
	    if (table->destroy)
		table->destroy ((*he)->data);
	    FREE (*he);
	    table->dbsize--;
	    *he = ptr;
	    return 0;
	}
    }
    return -1;
}

void
free_hash (HASH * h)
{
    HASHENT *he, *ptr;
    int i;

    ASSERT (h != 0);
    /* destroy remaining entries */
    for (i = 0; i < h->numbuckets; i++)
    {
	he = h->bucket[i];
	while (he)
	{
	    ptr = he;
	    he = he->next;
	    if (h->destroy)
		h->destroy (ptr->data);
	    FREE (ptr);
	}
    }
    FREE (h->bucket);
    FREE (h);
}

void
hash_foreach (HASH *h, void (*func) (void *, void *), void *funcdata)
{
    HASHENT *he, *ptr;
    int i;

    for (i = 0; i < h->numbuckets; i++)
    {
	he = h->bucket[i];
	while (he)
	{
	    /* we use a temp pointer here so that we can remove this entry
	       from the hash table inside of `func' and not cause problems
	       iterating the rest of the bucket */
	    ptr = he;
	    he = he->next;
	    func (ptr->data, funcdata);
	}
    }
}
