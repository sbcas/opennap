/* Copyright (C) 1999 drscholl@hotmail.com
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <string.h>
#include "opennap.h"
#include "debug.h"

/* change the user level for a user */
/* [ :<nick> ] <user> <level> */
void
level (CONNECTION *con, char *pkt)
{
    char *fields[2];
    USER *user;

    ASSERT (VALID (con));

    /* NOTE: we implicity trust that messages we receive from other servers
       are authentic, so we don't check the user privileges here.  we have
       to trust that the peer servers perform due dilegence before sending
       a message to us, otherwise we could never propogate initial user
       levels across all servers */
    if (con->class == CLASS_SERVER)
    {
	/* skip over who set the user level */
	pkt = strchr (pkt, ' ');
	if (!pkt)
	{
	    log ("level(): request contained too few fields");
	    return;
	}
	pkt++;
    }
    else
    {
	ASSERT (VALID (con->user));
	if ((con->user->flags & FLAG_ADMIN) == 0)
	{
	    log ("level(): user %s is not admin", con->user->nick);
	    return;
	}
    }

    if (split_line (fields, sizeof (fields) / sizeof (char *), pkt) != 2)
    {
	log ("level(): malformed client request");
	return;
    }

    user = hash_lookup (Users, fields[0]);
    if (!user)
    {
	if (con->class == CLASS_USER)
	    nosuchuser (con, fields[0]);
	else
	    log ("level(): user synch error, can't locate user %s", fields[0]);
	return;
    }

    ASSERT (VALID (user));

    /* clear existing flags */
    user->flags &= ~(FLAG_ADMIN | FLAG_MODERATOR);
    if (strcasecmp ("admin", fields[1]) == 0)
	user->flags |= FLAG_ADMIN;
    else if (strcasecmp ("moderator", fields[1]) == 0)
	user->flags |= FLAG_MODERATOR;
    else if (strcasecmp ("user", fields[1]) != 0)
	return; /* invalid video */

    /* pass the message to our peer servers if this came from a local user */
    if (con->class == CLASS_USER && Num_Servers)
    {
	pass_message_args (con, MSG_CLIENT_SETUSERLEVEL, ":%s %s %s",
		con->user->nick, user->nick, fields[1]);
    }
}
