/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#ifndef debug_h
#define debug_h

#if DEBUG

#include <stdio.h>
#define ASSERT(x) {if(!(x)){printf("assertion failed in %s, line %d: %s\n",__FILE__,__LINE__,#x);}}

#include <sys/types.h>

#define FREE(p) debug_free(p,__FILE__,__LINE__)
#define MALLOC(s) debug_malloc(s,__FILE__,__LINE__)
#define REALLOC(p,s) debug_realloc(p,s,__FILE__,__LINE__)
#define CALLOC(n,s) debug_calloc(n,s,__FILE__,__LINE__)
#define STRDUP(s) debug_strdup(s,__FILE__,__LINE__)
#define CLEANUP debug_cleanup
#define VALID debug_valid

/* internal functions, DO NOT CALL DIRECTLY -- use the above macros */
void debug_free (void *, const char *, int);
void *debug_malloc (size_t, const char *, int);
void *debug_calloc (size_t, size_t, const char *, int);
void *debug_realloc (void *, size_t, const char *, int);
char *debug_strdup (const char *, const char *, int);
void debug_cleanup (void);
int debug_valid (void *);

#else

#define FREE free
#define MALLOC malloc
#define CALLOC calloc
#define REALLOC realloc
#define STRDUP strdup
#define CLEANUP
#define VALID

#endif /* DEBUG */

#endif /* debug_h */
