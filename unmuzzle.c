/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include "opennap.h"
#include "debug.h"

/* [ :<nick> ] <user> */
HANDLER (unmuzzle)
{
    USER *user;

    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &user) != 0)
	return;

    if (user->level < LEVEL_MODERATOR)
    {
	if (con->class == CLASS_USER)
	    permission_denied (con);
	return;
    }

    /* find the target of the unmuzzle */
    user = hash_lookup (Users, pkt);
    if (!user)
    {
	if (con->class == CLASS_USER)
	    nosuchuser (con, pkt);
	return;
    }
    ASSERT (validate_user (user));

    user->muzzled = 0;

    /* if the user that issued the command is local, notify our peer servers */
    if (con->class == CLASS_USER && Num_Servers)
    {
	ASSERT (VALID (con->user));
	pass_message_args (con, MSG_CLIENT_UNMUZZLE, ":%s %s",
		  con->user->nick, user->nick);
    }
}
