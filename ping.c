/* Copyright (C) 1999 drscholl@hotmail.com
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include "opennap.h"
#include "debug.h"

/* [ :<user> ] <user> */
static void
ping_wrapper (CONNECTION *con, char *pkt, int msg)
{
    USER *orig, *user;

    ASSERT (VALID (con));

    if (pop_user (con, &pkt, &orig) != 0)
	return;

    user = hash_lookup (Users, pkt);
    if (!user)
    {
	if (con->class == CLASS_USER)
	{
	    send_cmd (con, MSG_SERVER_NOSUCH, "ping failed, %s is not online",
		pkt);
	}
	return;
    }

    if (user->con)
    {
	/* local user */
	send_cmd (user->con, msg, "%s", orig->nick);
    }
    else if (con->class == CLASS_USER)
    {
	/* remote user */
	send_cmd (user->serv, msg, ":%s %s", orig->nick, user->nick);
    }
}

void
ping (CONNECTION *con, char *pkt)
{
    ASSERT (VALID (con));
    ping_wrapper (con, pkt, MSG_SERVER_PING);
}

void
pong (CONNECTION *con, char *pkt)
{
    ASSERT (VALID (con));
    ping_wrapper (con, pkt, MSG_SERVER_PONG);
}
