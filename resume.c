/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

/* packet contains: <checksum> <filesize> */
HANDLER (resume)
{
    char *av[2];
    FLIST *flist;
    LIST *ptr;
    DATUM *d;
    int fsize;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    CHECK_USER_CLASS ("resume");

    if (split_line (av, sizeof (av) / sizeof (char *), pkt) != 2)
    {
	log ("resume(): wrong number of av");
	return;
    }
    
    fsize = atoi (av[1]);

    /* search the database for a list of all files which match this hash */
    flist = hash_lookup (MD5, av[0]);
    if (flist)
    {
	for (ptr = flist->list; ptr; ptr = ptr->next)
	{
	    d = (DATUM *) ptr->data;
	    if (d->size == fsize)
	    {
		ASSERT (validate_connection (d->user));
		send_cmd (con, MSG_SERVER_RESUME_MATCH,
			"%s %lu %d \"%s\" %s %d %hu",
			d->user->nick, d->user->host, d->user->port,
			d->filename, d->hash, d->size, d->user->speed);
	    }
	}
    }

    send_cmd (con, MSG_SERVER_RESUME_MATCH_END, "");
}
