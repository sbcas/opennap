/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include "opennap.h"
#include "debug.h"

/* [ :<user> ] <user> */
static void
ping_wrapper (CONNECTION *con, char *pkt, int msg)
{
    USER *orig, *user;

    ASSERT (validate_connection (con));

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
    ASSERT (validate_user (user));

    if (user->con) /* local user */
	send_cmd (user->con, msg, "%s", orig->nick);
    else if (con->class == CLASS_USER) /* remote user */
	send_cmd (user->serv, msg, ":%s %s", orig->nick, user->nick);
}

HANDLER (ping)
{
    ASSERT (validate_connection (con));
    ping_wrapper (con, pkt, MSG_SERVER_PING);
}

HANDLER (pong)
{
    ASSERT (validate_connection (con));
    ping_wrapper (con, pkt, MSG_SERVER_PONG);
}
