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
#include <errno.h>
#include <ctype.h>
#include "opennap.h"
#include "debug.h"

HASH *Filter = 0;

void
load_filter (void)
{
    char path[_POSIX_PATH_MAX];
    char buf[128], *token;
    int len;
    FILE *fp;

    if (Filter)
	free_hash (Filter);
    Filter = hash_init (257, free_pointer);

    snprintf (path, sizeof (path), "%s/filter", Config_Dir);
    fp = fopen (path, "r");
    if (!fp)
    {
	if (errno != ENOENT)
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
	/* no need to convert to lowercase since the hash table is
	 * case-insensitive
	 */
	token = STRDUP (buf);
	hash_add (Filter, token, token);
    }
    fclose (fp);
}

int
is_filtered (const char *s)
{
    return (hash_lookup (Filter, s) != 0);
}
