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
	if (ISUSER (con))
	{
	    send_cmd (con, MSG_SERVER_NOSUCH, "ping failed, %s is not online",
		nick);
	}
	return;
    }

    if (ISUSER (user->con))
    {
	if (!is_ignoring(user->con->uopt->ignore,orig->nick))
	    send_cmd (user->con, tag, "%s%s%s", orig->nick, pkt ? " " : "",
		    NONULL (pkt));
	else
	    send_user(orig,MSG_SERVER_NOSUCH,"%s is ignoring you",
		    user->nick);
    }
    else
    {
	/* send the message to the server which this user appears to be
	   behind */
	send_cmd (user->con, tag, ":%s %s%s%s", orig->nick, user->nick,
		pkt ? " " : "", NONULL (pkt));
    }
}
