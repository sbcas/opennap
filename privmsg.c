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

/* loopback command for allowing mods using the windows client to execute
   opennap comamnds */
static void
operserv (CONNECTION * con, char *pkt)
{
    char *cmd = next_arg (&pkt);
    unsigned short tag, len;
    char ch = 0;

    if (!strcasecmp ("chanlevel", cmd))
	tag = MSG_CLIENT_CHANNEL_LEVEL;
    else if (!strcasecmp ("links", cmd))
	tag = MSG_CLIENT_LINKS;
    else if (!strcasecmp ("stats", cmd))
	tag = MSG_CLIENT_USAGE_STATS;
    else if (!strcasecmp ("connect", cmd))
	tag = MSG_CLIENT_CONNECT;
    else if (!strcasecmp ("disconnect", cmd))
	tag = MSG_CLIENT_DISCONNECT;
    else if (!strcasecmp ("killserver", cmd))
	tag = MSG_CLIENT_KILL_SERVER;
    else if (!strcasecmp ("register", cmd))
	tag = MSG_CLIENT_REGISTER_USER;
    else
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "Unknown OperServ command: %s", cmd);
	return;
    }
    if (pkt)
	len = strlen (pkt);
    else
    {
	/* most of the handler routines expect `pkt' to be non-NULL so pass
	   a dummy value here */
	pkt=&ch;
	len=0;
    }
    dispatch_command (con, tag, len, pkt);
}

/* handles private message commands */
/* [ :<nick> ] <user> <text> */
HANDLER (privmsg)
{
    char *ptr;
    USER *sender, *user /* recip */;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    ptr = pkt; /* save the start offset of pkt for length check */
    if (pop_user (con, &pkt, &sender) != 0)
	return;
    ASSERT (validate_user (sender));

    /* prevent DoS attack againt windows napster client */
    if (len - (pkt - ptr) > 180)
    {
	log ("privmsg(): truncated %d byte message from %s", len, sender->nick);
	pkt[180] = 0;
    }

    /* check to see if the recipient of the message is local */
    ptr = next_arg_noskip (&pkt);
    if (!pkt)
    {
	log ("privmsg(): malformed message from %s", sender->nick);
	return;
    }

    if (ISUSER (con) && sender->level > LEVEL_USER &&
	    !strcasecmp(ptr,"operserv"))
    {
	operserv(con,pkt);
	return;
    }

    /* find the recipient */
    user = hash_lookup (Users, ptr);
    if (!user)
    {
	if (ISUSER (con))
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
