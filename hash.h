/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#ifndef hash_h
#define hash_h

#include <sys/types.h>

typedef void (*hash_destroy) (void *);

typedef struct _hashent
{
  const char *key;
  void *data;
  struct _hashent *next;
}
HASHENT;

typedef struct _hash
{
  HASHENT **bucket;
  int numbuckets;
  int dbsize; /* # of elements in the table */
  hash_destroy destroy;
}
HASH;

typedef void (*hash_callback_t) (void *, void *);

HASH *hash_init (int, hash_destroy);
int hash_add (HASH *, const char *, void *);
void *hash_lookup (HASH *, const char *);
int hash_remove (HASH *, const char *);
void free_hash (HASH *);
void hash_foreach (HASH *h, hash_callback_t, void *funcdata);

#endif /* hash_h */
