/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"
#include "debug.h"

/* [ :<nick> ] <user> [ "<reason>" ] */
HANDLER (unmuzzle)
{
    USER *sender, *user;
    int ac = -1;
    char *av[2];
    USERDB *db;

    (void) len;
    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &sender) != 0)
	return;
    if (pkt)
	ac = split_line (av, FIELDS (av), pkt);
    if (ac < 1)
    {
	log ("muzzle(): too few parameters");
	print_args (ac, av);
	unparsable (con);
	return;
    }
    /* find the target of the unmuzzle */
    user = hash_lookup (Users, av[0]);
    if (!user)
    {
	nosuchuser (con, av[0]);
	return;
    }
    ASSERT (validate_user (user));

    if (sender->level <= user->level && sender->level != LEVEL_ELITE)
    {
	log ("unmuzzle(): %s has no privilege to unmuzzle %s",
	     sender->nick, user->nick);
	permission_denied (con);
	return;
    }

    if (!user->muzzled)
    {
	log("unmuzzle(): %s is not muzzled", user->nick);
	if(ISUSER(con))
	    send_cmd(con,MSG_SERVER_NOSUCH,"%s is not muzzled",user->nick);
	return;
    }

    user->muzzled = 0;

    db=hash_lookup(User_Db,user->nick);
    ASSERT (db != 0);	/* should have been created when muzzled */
    if(db)
	db->muzzled = 0;

    /* relay to peer servers */
    if (ac > 1)
	pass_message_args (con, tag, ":%s %s \"%s\"",
			   sender->nick, user->nick, av[1]);
    else
	pass_message_args (con, tag, ":%s %s",
			   sender->nick, user->nick);

    notify_mods (MUZZLELOG_MODE, "%s unmuzzled %s: %s", sender->nick,
		 user->nick, ac > 1 ? av[1] : "");

    /* notify the user they have been unmuzzled */
    if (user->local)
	send_cmd (user->con, MSG_SERVER_NOSUCH,
		  "You have been unmuzzled by %s: %s", sender->nick,
		  ac > 1 ? av[1] : "");
}
