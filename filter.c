/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

/* simple filtering mechanism to weed out entries which have too many
 * matches.  this used to be hardcoded, but various servers will need
 * to tailor this to suit their own needs.  see sample.filter for an
 * example list of commonly occuring words
 */

#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

typedef struct filter
{
    int field;			/* first char */
    LIST *entry;		/* list of tokens with the first char skipped */
    struct filter *next;	/* next filter entry */
}
FILTER;

static FILTER *Filter = 0;

void
load_filter (void)
{
    char path[_POSIX_PATH_MAX];
    char buf[128];
    FILTER **filt, *tmp;
    LIST *list;
    int len;
    FILE *fp;

    snprintf (path, sizeof (path), "%s/filter", Config_Dir);
    fp = fopen (path, "r");
    if (!fp)
    {
	if(errno!=ENOENT)
	    log ("load_filter(): fopen: %s: %s (errno %d)",
		    path, strerror (errno), errno);
	return;
    }
    while (fgets (buf, sizeof (buf) - 1, fp))
    {
	len = strlen (buf);
	while (len > 0 && isspace (buf[len - 1]))
	    len--;
	buf[len] = 0;
	strlower (buf);
	for (filt = &Filter; *filt; filt = &(*filt)->next)
	{
	    if ((*filt)->field >= buf[0])
		break;
	}
	if (!*filt || (*filt)->field != buf[0])
	{
	    tmp = CALLOC (1, sizeof (FILTER));
	    tmp->field = buf[0];
	    tmp->next = *filt;
	    *filt = tmp;
	}
	list = CALLOC (1, sizeof (list));
	list->data = STRDUP (buf + 1);
	list->next = (*filt)->entry;
	(*filt)->entry = list;
    }
    fclose (fp);
}

int
is_filtered (const char *s)
{
    FILTER *filt;
    LIST *list;

    for (filt = Filter; filt; filt = filt->next)
    {
	if (*s == filt->field)
	    break;
	if (*s > filt->field)
	    return 0;
    }
    if (filt)
    {
	s++;
	for (list = filt->entry; list; list = list->next)
	{
	    if (!strcmp (s, list->data))
		return 1;
	}
    }
    return 0;
}

void
free_filter (void)
{
    FILTER *tmp;

    while (Filter)
    {
	tmp = Filter;
	Filter = Filter->next;
	list_free (tmp->entry, free_pointer);
	FREE (tmp);
    }
}
