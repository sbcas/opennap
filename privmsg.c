/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdio.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <string.h>
#include "opennap.h"
#include "debug.h"

/* handles private message commands */
/* [ :<nick> ] <user> <text> */
HANDLER (privmsg)
{
    char *ptr;
    USER *sender, *user /* recip */;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &sender) != 0)
	return;
    ASSERT (validate_user (sender));

    /* check to see if the recipient of the message is local */
    ptr = strchr (pkt, ' ');
    if (ptr == 0)
    {
	log ("privmsg(): malformed message from %s: %s", sender->nick, pkt);
	return;
    }
    *ptr++ = 0;			/* kill the rest of the line */

    /* find the recipient */
    user = hash_lookup (Users, pkt);
    if (!user)
    {
	if (con->class == CLASS_USER)
	    nosuchuser (con, pkt);
	return;
    }
    ASSERT (validate_user (user));

    /*  locally connected user */
    if (user->con)
    {
	ASSERT (validate_connection (user->con));

	/*reconsitute the msg */
	send_cmd (user->con, MSG_CLIENT_PRIVMSG, "%s %s", sender->nick, ptr);
    }
    else if (con->class == CLASS_USER)
    {
	/* pass the message on to our peers since the recipient isn't
	   local.  we know which server the client is behind, so we just
	   need to send one copy */
	ASSERT (user->serv != 0);
	send_cmd (user->serv, MSG_CLIENT_PRIVMSG, ":%s %s %s",
		sender->nick, user->nick, ptr);
    }
}
