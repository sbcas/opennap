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
    ptr = next_arg_noskip (&pkt);
    if (!pkt)
    {
	log ("privmsg(): malformed message from %s", sender->nick);
	return;
    }

    /* find the recipient */
    user = hash_lookup (Users, ptr);
    if (!user)
    {
	if (con->class == CLASS_USER)
	    nosuchuser (con, ptr);
	return;
    }
    ASSERT (validate_user (user));

    /*  locally connected user */
    if (user->local)
    {
	ASSERT (validate_connection (user->con));

	/*reconsitute the msg */
	send_cmd (user->con, MSG_CLIENT_PRIVMSG, "%s %s", sender->nick, pkt);
    }
    else
    {
	/* pass the message on to our peers since the recipient isn't
	   local.  we know which server the client is behind, so we just
	   need to send one copy */
	ASSERT (user->con->class == CLASS_SERVER);
	send_cmd (user->con, MSG_CLIENT_PRIVMSG, ":%s %s %s",
		sender->nick, user->nick, pkt);
    }
}

/* this is not needed, use send_user() instead */
#if 0
/* 10404 <user> <message>
   This message is used by servers to send a 404 message to a user on a remote
   server. */
HANDLER (priv_errmsg)
{
    char *nick;
    USER *user;

    ASSERT (validate_connection (con));
    CHECK_SERVER_CLASS ("priv_errmsg");
    (void) tag;
    (void) len;
    nick = next_arg (&pkt);
    user = hash_lookup (Users, nick);
    if (!user)
    {
	log ("priv_errmsg(): unable to locate user %s", nick);
	return;
    }
    ASSERT (validate_user (user));
    if (user->local)
    {
	/* local user, deliver message */
	ASSERT (validate_connection (user->con));
	send_cmd (user->con, MSG_SERVER_NOSUCH, "%s", pkt);
    }
}
#endif
