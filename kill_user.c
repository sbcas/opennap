/* Copyright (C) 2000 drscholl@sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <string.h>
#include "opennap.h"
#include "debug.h"

/* request to kill (disconnect) a user */
/* [ :<nick> ] <user> */
void
kill_user (CONNECTION * con, char *pkt)
{
    USER *user;

    ASSERT (VALID (con));

    if (con->class == CLASS_USER)
    {
	/* check to make sure this user has privilege */
	ASSERT (VALID (con->user));
	if ((con->user->flags & FLAG_ADMIN) == 0)
	{
	    log ("kill_user(): %s tried to kill %s", con->user->nick, pkt);
	    permission_denied (con);
	    return;
	}
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
	pkt = strchr (pkt, ' ');
	if (!pkt)
	{
	    log ("kill_user(): too few arguments in server message");
	    return;
	}
	pkt++;
    }

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
    ASSERT (VALID (user));

    /* local user issued the kill, notify peers */
    if (con->class == CLASS_USER && Num_Servers)
    {
	pass_message_args (con, MSG_CLIENT_KILL, ":%s %s", con->user->nick,
	    user->nick);
    }

    /* forcefully close the client connection if local, otherwise remove
       from global user list */
    if (user->con)
	remove_connection (user->con);
    else
	hash_remove (Users, user->nick);
}
