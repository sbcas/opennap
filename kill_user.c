/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include "opennap.h"
#include "debug.h"

/* send a message to all local mods */
void
notify_mods (unsigned int level, const char *fmt, ...)
{
    int i, len;
    va_list ap;

    va_start (ap, fmt);
    vsnprintf (Buf + 4, sizeof (Buf) - 4, fmt, ap);
    va_end (ap);
    set_tag (Buf, MSG_SERVER_NOSUCH);
    len = strlen (Buf + 4);
    set_len (Buf, len);
    for (i = 0; i < Max_Clients; i++)
    {
	if (Clients[i] && ISUSER (Clients[i]) &&
	    Clients[i]->user->level >= LEVEL_MODERATOR &&
	    (Clients[i]->uopt->usermode & level))
	    queue_data (Clients[i], Buf, len + 4);
    }
}

/* request to kill (disconnect) a user */
/* [ :<nick> ] <user> [ "<reason>" ] */
HANDLER (kill_user)
{
    char *av[2], *killernick;
    int ac;
    USER *killer = 0, *user;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    if (ISUSER (con))
    {
	/* check to make sure this user has privilege */
	ASSERT (validate_user (con->user));
	killer = con->user;
	killernick = killer->nick;
    }
    else
    {
	ASSERT (ISSERVER (con));

	/* skip over who did the kill */
	if (*pkt != ':')
	{
	    log ("kill_user(): malformed server message");
	    return;
	}
	pkt++;
	killernick = next_arg (&pkt);
	if (!pkt)
	{
	    log ("kill_user(): too few arguments in server message");
	    return;
	}
	if (!is_server (killernick))
	{
	    killer = hash_lookup (Users, killernick);
	    if (!killer)
	    {
		log ("kill_user(): could not find user %s", killernick);
		return;
	    }
	}
    }

    ac = split_line (av, FIELDS (av), pkt);
    if (ac < 1)
    {
	unparsable (con);
	return;
    }

    /* find the user to kill */
    user = hash_lookup (Users, av[0]);
    if (!user)
    {
	nosuchuser (con);
	return;
    }
    ASSERT (validate_user (user));

    /* check for permission */
    if (killer && user->level >= killer->level && killer->level != LEVEL_ELITE)
    {
	permission_denied (con);
	return;
    }

    if(ac>1)
	truncate_reason(av[1]);
#define REASON ((ac > 1) ? av[1] : "")

    pass_message_args (con, MSG_CLIENT_KILL, ":%s %s \"%s\"",
		       killernick, user->nick, REASON);

    /* notify mods+ that this user was killed */
    notify_mods (KILLLOG_MODE, "%s killed %s: %s", killernick, user->nick,
		 REASON);

    /* forcefully close the client connection if local, otherwise remove
       from global user list */
    if (user->local)
    {
	user->con->destroy = 1;
	/* notify user they were killed */
	send_cmd (user->con, MSG_SERVER_NOSUCH,
		  "You have been killed%s%s: %s",
		  killer && killer->cloaked ? "" : " by ",
		  killer && killer->cloaked ? "" : killernick, REASON);
    }
    /* remote user, just remove from the global list */
    else
	hash_remove (Users, user->nick);
}
