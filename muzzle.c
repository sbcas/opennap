/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <stdlib.h>
#include <time.h>
#include "opennap.h"
#include "debug.h"

/* [ :<nick> ] <user-to-muzzle> <time> */
HANDLER (muzzle)
{
    USER *sender, *user;
    char *fields[2];

    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &sender) != 0)
	return;

    ASSERT (validate_user (sender));

    if (split_line (fields, sizeof (fields) / sizeof (char *), pkt) != 2)
    {
	log ("muzzle(): malformed client request");
	return;
    }

    /* find the user to be muzzled */
    user = hash_lookup (Users, fields[0]);
    if (!user)
    {
	if (con->class == CLASS_USER)
	    nosuchuser (con, fields[0]);
	else
	    log ("muzzle(): can't locate user %s", fields[0]);
	return;
    }
    ASSERT (validate_user (user));

    /* ensure that this user has privilege to execute the command */
    if (user->level >= sender->level)
    {
	if (con->class == CLASS_USER)
	    permission_denied (con);
	return;
    }

    /* set the time until which the user is muzzled */
    user->muzzled = time (0) + atoi (fields[1]);

    if (con->class == CLASS_USER && Num_Servers)
    {
	ASSERT (VALID (con->user));
	pass_message_args (con, MSG_CLIENT_MUZZLE, ":%s %s %s", con->user->nick,
		user->nick, fields[1]);
    }

    /* notify the user they have been muzzled */
    if (user->con)
	send_cmd (user->con, MSG_SERVER_NOSUCH, "You have been muzzled.");

    /* notify mods+ of this action */
    notify_mods ("%s has muzzled %s.", sender->nick, user->nick);
}
