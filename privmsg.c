/* Copyright (C) 1999 drscholl@hotmail.com
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "opennap.h"
#include "debug.h"

/* handles private message commands */
/* [ :<nick> ] <user> <text> */
void
privmsg (CONNECTION * con, char *pkt)
{
    char *ptr;
    USER *sender, *user /* recip */;

    ASSERT (VALID (con));

    if (pop_user (con, &pkt, &sender) != 0)
	return;

    /* check to see if the recipient of the message is local */
    ptr = strchr (pkt, ' ');
    if (ptr == 0)
    {
	/* malformed message, just drop it silently */
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
    ASSERT (VALID (user));

    /*  locally connected user */
    if (user->con)
    {
	/*reconsitute the msg */
	send_cmd (user->con, MSG_CLIENT_PRIVMSG, "%s %s", sender->nick, ptr);

	/* stupid hack until we can get proper support in clients */
	if (con->class == CLASS_USER && strncmp (".CONNECT", ptr, 8) == 0)
	    try_connect_privmsg (ptr + 8);
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
