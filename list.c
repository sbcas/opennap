/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdlib.h>
#include "list.h"
#include "debug.h"

/* remove the element matching `data' from the list */
LIST *
list_delete (LIST *list, void *data)
{
    LIST **ptr, *tmp;

    ASSERT (list != 0);
    ASSERT (data != 0);
    for (ptr = &list; *ptr; ptr = &(*ptr)->next)
    {
	if ((*ptr)->data == data)
	{
	    tmp = *ptr;
	    *ptr = (*ptr)->next;
	    FREE (tmp);
	    break;
	}
    }
    return list;
}

LIST *
list_append (LIST * l, LIST *b)
{
    LIST **r = &l;

    while (*r)
	r = &(*r)->next;
    *r = b;
    return l;
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
