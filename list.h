/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#ifndef list_h
#define list_h

typedef struct list LIST;

struct list {
    void *data;
    LIST *next;
};

/* prototype for list_free() callback function */
typedef void (*list_destroy_t) (void *);

/* create a new list struct with the given data */
LIST *list_new (void *);

/* removes the specified element from the list */
LIST *list_delete (LIST *, void *);

/* append an element to the list */
LIST *list_append (LIST *, LIST *);

LIST *list_append_data (LIST *, void *);

/* free a list element */
void list_free (LIST *, list_destroy_t);

/* return the number of items in a list */
int list_count (LIST *);

LIST *list_find (LIST *, void *);

int list_validate (LIST *);

#if DEBUG
#define LIST_NEW(p,d) { p = CALLOC (1, sizeof (LIST)); if (p) (p)->data = d; }
#else
#define LIST_NEW(p,d) p = list_new (d)
#endif /* DEBUG */

#endif /* list_h */
