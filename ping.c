/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
#include "opennap.h"
#include "debug.h"

/* [ :<user> ] <user> [ <optional args> ] */
HANDLER (ping)
{
    USER *orig, *user;
    char *nick;

    (void) len;
    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &orig) != 0)
	return;
    nick = pkt;
    pkt = strchr (nick, ' ');
    if (pkt)
	*pkt++ = 0;

    user = hash_lookup (Users, nick);
    if (!user)
    {
	if (con->class == CLASS_USER)
	{
	    send_cmd (con, MSG_SERVER_NOSUCH, "ping failed, %s is not online",
		nick);
	}
	return;
    }
    ASSERT (validate_user (user));

    if (user->con) /* local user */
	send_cmd (user->con, tag, "%s%s%s", orig->nick, pkt ? " " : "",
		NONULL (pkt));
    else if (con->class == CLASS_USER) /* remote user */
	send_cmd (user->serv, tag, ":%s %s%s%s", orig->nick, user->nick,
		pkt ? " " : "", NONULL (pkt));
}
