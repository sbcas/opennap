/* Copyright (C) 2000 edwards@bitchx.dimension6.com
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

/*
 * written by Colten Edwards.
 */

#include <string.h>
#include <stdio.h>
#include "opennap.h"
#include "debug.h"

static char *User_Levels[] = { "ERROR", "BAN", "CHANGE", "CHANNEL",
    "KILL", "LEVEL", "SERVER", "MUZZLE", "PORT", "TOPIC", "WALLOP",
    "CLOAK", ""
};


/* 10203 [mode] */
HANDLER (user_mode_cmd)
{
    USER *sender;
    int neg = 0, i, p;
    unsigned int level = 0;
    char *av;

    (void) tag;
    (void) len;
    CHECK_USER_CLASS ("user_mode");
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &sender))
	return;
    if (!pkt || !*pkt)
    {
	char buffer[250];
	int buflen;

	if (sender->con->uopt->usermode == 0)
	    strcpy (buffer, "NONE");
	else
	{
	    buffer[0] = 0;
	    for (i = 0, p = 1; *User_Levels[i]; i++, p <<= 1)
	    {
		if (sender->con->uopt->usermode & p)
		{
		    buflen = strlen (buffer);
		    snprintf (buffer + buflen, sizeof (buffer) - buflen,
			      "%s%s", buflen > 0 ? " " : "", User_Levels[i]);
		}
	    }
	}
	send_cmd (con, MSG_SERVER_USER_MODE, "%s", buffer);
	return;
    }
    level = con->uopt->usermode;
    while ((av = next_arg (&pkt)))
    {
	if (!strcasecmp (av, "ALL"))
	    level = LOGALL_MODE;
	else if (!strcasecmp (av, "NONE"))
	    level = 0;
	else if (*av == '-')
	{
	    neg = 1;
	    av++;

	}
	else
	    neg = 0;
	for (i = 0, p = 1; *User_Levels[i]; i++, p <<= 1)
	{
	    if (!strcasecmp (av, User_Levels[i]))
	    {
		if (neg)
		    level &= (LOGALL_MODE ^ p);
		else
		    level |= p;
		break;
	    }
	}
    }
    if (sender->con->uopt->usermode != level)
	sender->con->uopt->usermode = level;
}
