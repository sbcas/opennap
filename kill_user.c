/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <string.h>
#include <stdarg.h>
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
    char *killernick, *reason;

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
	killernick = pkt;
	pkt = strchr (pkt, ' ');
	if (!pkt)
	{
	    log ("kill_user(): too few arguments in server message");
	    return;
	}
	*pkt++ = 0;
    }

    /* extract the reason */
    reason = strchr (pkt, ' ');
    if (reason)
	*reason++ = 0;

    /* find the user to kill*/
    user = hash_lookup (Users, pkt);
    if (!user)
    {
	if (con->class == CLASS_USER)
	    nosuchuser (con, pkt);
	else
	    log ("kill_user(): could not locate user %s", pkt);
	return;
    }
    ASSERT (validate_user (user));

    /* check for permission */
    if (killer && (user->level >= killer->level))
    {
	permission_denied (con);
	return;
    }

    /* local user issued the kill, notify peers */
    if (con->class == CLASS_USER)
    {
	if (Num_Servers)
	    pass_message_args (con, MSG_CLIENT_KILL, ":%s %s %s",
		con->user->nick, user->nick, reason ? reason : "");
    }

    /* notify mods+ that this user was killed */
    notify_mods ("%s killed user %s: %s", killernick, user->nick,
	    reason ? reason : "");

    /* notify user they were killed */
    if (user->con)
    {
	send_cmd (user->con, MSG_SERVER_NOSUCH, "you have been killed by %s",
	    killernick);
	send_queued_data (user->con); /* flush now so message is not lost */
    }

    /* forcefully close the client connection if local, otherwise remove
       from global user list */
    if (user->con)
	remove_connection (user->con);
    else
	hash_remove (Users, user->nick);

}
