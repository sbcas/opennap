/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
#include "opennap.h"
#include "debug.h"

/* [ :<nick> ] <user-to-muzzle> [ <reason> ] */
HANDLER (muzzle)
{
    USER *sender, *user;
    char *nick;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &sender) != 0)
	return;

    ASSERT (validate_user (sender));

    nick = next_arg (&pkt);

    /* find the user to be muzzled */
    user = hash_lookup (Users, nick);
    if (!user)
    {
	if (ISUSER (con))
	    nosuchuser (con, nick);
	return;
    }
    ASSERT (validate_user (user));

    /* ensure that this user has privilege to execute the command */
    if (sender->level < LEVEL_ELITE && user->level >= sender->level)
    {
	if (ISUSER (con))
	    permission_denied (con);
	return;
    }

    /* relay to peer servers */
    pass_message_args (con, MSG_CLIENT_MUZZLE, ":%s %s %s",
		       sender->nick, user->nick, NONULL (pkt));

    user->muzzled = 1;

    /* notify the user they have been muzzled */
    if (user->local)
	send_cmd (user->con, MSG_SERVER_NOSUCH,
		  "You have been muzzled by %s: %s", sender->nick,
		  NONULL (pkt));

    /* notify mods+ of this action */
    notify_mods ("%s has muzzled %s: %s", sender->nick, user->nick,
		 NONULL (pkt));
}
