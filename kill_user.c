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
notify_mods (const char *fmt, ...)
{
    char buf[128];/* send_cmd() uses Buf so we can't use it here */
    int i;
    va_list ap;

    va_start (ap, fmt);
    vsnprintf (buf, sizeof (buf), fmt, ap);
    va_end (ap);
    for (i = 0; i < Num_Clients; i++)
    {
	if (Clients[i] && Clients[i]->class == CLASS_USER &&
		Clients[i]->user->level >= LEVEL_MODERATOR)
	    send_cmd (Clients[i], MSG_SERVER_NOSUCH, buf);
    }
}

/* request to kill (disconnect) a user */
/* [ :<nick> ] <user> [ <reason> ] */
HANDLER (kill_user)
{
    USER *killer = 0, *user;
    char *killernick, *target;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    if (con->class == CLASS_USER)
    {
	/* check to make sure this user has privilege */
	ASSERT (validate_user (con->user));
	killer = con->user;
	killernick = killer->nick;
    }
    else
    {
	ASSERT (con->class == CLASS_SERVER);

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
    }

    /* extract the target of the kill */
    target = next_arg (&pkt);

    /* find the user to kill*/
    user = hash_lookup (Users, target);
    if (!user)
    {
	log ("kill_user(): could not locate user %s", target);
	if (con->class == CLASS_USER)
	    nosuchuser (con, target);
	return;
    }
    ASSERT (validate_user (user));

    /* check for permission */
    if (killer && killer->level < LEVEL_ELITE && user->level >= killer->level)
    {
	permission_denied (con);
	return;
    }

    /* local user issued the kill, notify peers */
    if (con->class == CLASS_USER && Num_Servers)
    {
	pass_message_args (con, MSG_CLIENT_KILL, ":%s %s %s",
	    con->user->nick, user->nick, NONULL (pkt));
    }

    /* log this action */
    log ("kill_user(): %s killed user %s: %s", killernick, user->nick,
	NONULL (pkt));

    /* notify mods+ that this user was killed */
    notify_mods ("%s killed user %s: %s", killernick, user->nick, NONULL (pkt));

    /* forcefully close the client connection if local, otherwise remove
       from global user list */
    if (user->con)
    {
	con->destroy = 1;
	/* notify user they were killed */
	send_cmd (user->con, MSG_SERVER_NOSUCH,
	    "you have been killed by %s: %s", killernick, NONULL (pkt));
    }
    /* remote user, just remove from the global list */
    else
	hash_remove (Users, user->nick);
}
