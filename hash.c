/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software disributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
#include <ctype.h>
#include "hash.h"
#include "debug.h"

/* a simple hash table.  keys are case insensitive for this application */

/* initialize a hash table.  `buckets' should be a prime number for maximum
   dispersion of entries into buckets */
HASH *
hash_init (int buckets, hash_destroy f)
{
    HASH *h = CALLOC (1, sizeof (HASH));
    h->numbuckets = buckets;
    h->bucket = CALLOC (buckets, sizeof (HASHENT *));
    h->destroy = f;
    return h;
}

static int
hash_string (HASH * table, const char *key)
{
    int sum = 0;
    for (;*key;key++)
	sum += tolower (*key);
    sum = sum % table->numbuckets;
    return sum;
}

void
hash_add (HASH * table, const char *key, void *data)
{
    HASHENT *he = CALLOC (1, sizeof (HASHENT));
    int sum;

    he->key = key;
    he->data = data;
    sum = hash_string (table, key);
    /* TODO: sort the members of the bucket */
    he->next = table->bucket[sum];
    table->bucket[sum] = he;
    table->dbsize++;
}

void *
hash_lookup (HASH * table, const char *key)
{
    HASHENT *he;
    int sum = hash_string (table, key);
    he = table->bucket[sum];
    while (he)
    {
	if (strcasecmp (key, he->key) == 0)
	    return he->data;
	he = he->next;
    }
    return 0;
}

void
hash_remove (HASH * table, const char *key)
{
    HASHENT *he, *last = 0;
    int sum = hash_string (table, key);
    he = table->bucket[sum];
    while (he)
    {
	if (strcasecmp (key, he->key) == 0)
	{
	    if (last)
		last->next = he->next;
	    else
		table->bucket[sum] = he->next;
	    if (table->destroy)
		table->destroy (he->data);
	    FREE (he);
	    table->dbsize--;
	    break;
	}
	last = he;
	he = he->next;
    }
}

void
free_hash (HASH * h)
{
    HASHENT *he, *ptr;
    int i;

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
