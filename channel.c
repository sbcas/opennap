/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

void
load_channels (void)
{
    char path[_POSIX_PATH_MAX], *av[4];
    FILE *fp;
    int ac, limit, level;
    CHANNEL *chan;

    snprintf (path, sizeof (path), "%s/channels", Config_Dir);
    fp = fopen (path, "r");
    if (!fp)
    {
	log ("load_channels(): %s: %s (errno %d)", path, strerror (errno),
	     errno);
	return;
    }
    while (fgets (Buf, sizeof (Buf), fp))
    {
	if (Buf[0] == '#' || Buf[0] == '\r' || Buf[0] == '\n')
	    continue;	/* blank or comment line */
	ac = split_line (av, FIELDS (av), Buf);
	if (ac < 3)
	{
	    log ("load_channels(): too few parameters for channel %s",
		 ac > 1 ? av[0] : "(unknown)");
	    continue;
	}
	level = get_level (av[2]);
	if (level == -1)
	{
	    log ("load_channels(): invalid level %s for channel %s",
		 av[2], av[0]);
	    continue;
	}
	limit = atoi (av[1]);
	if (limit < 0 || limit > 65535)
	{
	    log ("load_channels(): invalid limit %d for channel %s",
		 limit, av[0]);
	    continue;
	}
	chan = CALLOC (1, sizeof (CHANNEL));
	if (chan)
	{
#if DEBUG
	    chan->magic = MAGIC_CHANNEL;
#endif
	    chan->name = STRDUP (av[0]);
	    if (ac > 3)
		chan->topic = STRDUP (av[3]);
	    chan->limit = limit;
	    chan->level = level;
	}
	if (hash_add (Channels, chan->name, chan))
	    free_channel (chan);
    }
}
