/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"
#include "debug.h"

/* [ :<nick> ] <user> */
HANDLER (unmuzzle)
{
    USER *sender, *user;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &sender) != 0)
	return;

    if (sender->level < LEVEL_MODERATOR)
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

    notify_mods ("%s unmuzzled %s.", sender->nick, user->nick);

    /* notify the user they have been unmuzzled */
    if (user->con)
	send_cmd (user->con, MSG_SERVER_NOSUCH,
	    "You have been unmuzzled by %s", sender->nick);
}
