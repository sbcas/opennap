/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdlib.h>
#include <stdio.h>
#include "list.h"
#include "debug.h"

LIST *
list_new (void *data)
{
    LIST *ptr = CALLOC (1, sizeof (LIST));
    if (ptr)
	ptr->data = data;
    else
	fprintf (stderr, "list_new(): OUT OF MEMORY");
    return ptr;
}

/* removes the specified element from the list */
void
list_remove (LIST **l)
{
    LIST *ptr;

    ASSERT (*l != 0);
    ptr = (*l)->next;
    FREE (*l);
    *l = ptr;
}

/* remove the element matching `data' from the list */
LIST *
list_delete (LIST *list, void *data)
{
    LIST **ptr;

    for (ptr = &list; *ptr; ptr = &(*ptr)->next)
    {
	if ((*ptr)->data == data)
	{
	    list_remove (ptr);
	    break;
	}
    }
    return list;
}

LIST *
list_append (LIST * l, void *data)
{
    LIST *r = l;

    if (!l)
    {
        l = r = list_new (data);
	if (!r)
	    return 0;
    }
    else
    {
        while (l->next)
            l = l->next;
        l->next = list_new (data);
	if (!l->next)
	    return r;
        l = l->next;
    }
    return r;
}

LIST *
list_concat (LIST *a, LIST *b)
{
    if (!a)
	return b;
    while (a && a->next)
	a = a->next;
    a->next = b;
    return a;
}

void
list_free (LIST *l, list_destroy_t cb)
{
    LIST *t;

    while (l)
    {
	t = l;
	l = l->next;
	if (cb)
	    cb (t->data);
	FREE (t);
    }
}

int
list_count (LIST *list)
{
    int count = 0;

    for(;list; list = list->next)
	count++;
    return count;
}

LIST *
list_find (LIST *list, void *data)
{
    for (; list; list = list->next)
	if (list->data == data)
	    return list;
    return 0;
}
