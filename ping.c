/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"
#include "debug.h"

/* [ :<user> ] <user> */
HANDLER (ping)
{
    USER *orig, *user;

    (void) len;
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
	send_cmd (user->con, tag, "%s", orig->nick);
    else if (con->class == CLASS_USER) /* remote user */
	send_cmd (user->serv, tag, ":%s %s", orig->nick, user->nick);
}
