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

/* removes the specified element from the list */
LIST *list_delete (LIST *, void *);

/* append an element to the list */
LIST *list_append (LIST *, LIST *);

/* free a list element */
void list_free (LIST *, list_destroy_t);

/* return the number of items in a list */
int list_count (LIST *);

LIST *list_find (LIST *, void *);

int list_validate (LIST *);

#endif /* list_h */
