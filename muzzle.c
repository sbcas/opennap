/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
#include "opennap.h"
#include "debug.h"

/* [ :<nick> ] <user-to-muzzle> [ "<reason>" ] */
HANDLER (muzzle)
{
    USER *sender, *user;
    char *av[2];
    int ac = -1;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &sender) != 0)
	return;

    ASSERT (validate_user (sender));

    if (pkt)
	ac = split_line (av, FIELDS (av), pkt);
    if (ac < 1)
    {
	log ("muzzle(): too few parameters");
	print_args (ac, av);
	unparsable (con);
	return;
    }

    /* find the user to be muzzled */
    user = hash_lookup (Users, av[0]);
    if (!user)
    {
	if (ISUSER (con))
	    nosuchuser (con, av[0]);
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

    if (user->muzzled)
    {
	log("muzzle(): %s is already muzzled",user->nick);
	if (ISUSER (con))
	    send_cmd(con,MSG_SERVER_NOSUCH,"%s is already muzzled",user->nick);
	return;
    }

    /* relay to peer servers */
    if (ac > 1)
	pass_message_args (con, MSG_CLIENT_MUZZLE, ":%s %s \"%s\"",
			   sender->nick, user->nick, av[1]);
    else
	pass_message_args (con, MSG_CLIENT_MUZZLE, ":%s %s",
			   sender->nick, user->nick);

    user->muzzled = 1;

    /* notify the user they have been muzzled */
    if (user->local)
	send_cmd (user->con, MSG_SERVER_NOSUCH,
		  "You have been muzzled by %s: %s", sender->nick,
		  ac > 1 ? av[1] : "");

    /* notify mods+ of this action */
    notify_mods (MUZZLELOG_MODE, "%s has muzzled %s: %s", sender->nick,
		 user->nick, ac > 1 ? av[1] : "");
}
