/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

/* [ :<sender> ] <target-user> [ "<reason>" ]
   muzzle/unmuzzle a user */
HANDLER (muzzle)
{
    USER *user, *sender = 0;
    char *av[2], *senderName;
    int ac = -1;
    USERDB *db;

    (void) len;
    ASSERT (validate_connection (con));

    /* sender might be a server so we don't use pop_user() here */
    if (ISSERVER (con))
    {
	if (*pkt != ':')
	{
	    log ("muzzle(): malformed server message (missing sender)");
	    return;
	}
	pkt++;
	senderName = next_arg (&pkt);
	/* check to see if this was issued by a real user */
	if (!is_server (senderName))
	{
	    sender = hash_lookup (Users, senderName);
	    if (!sender)
	    {
		log ("muzzle(): could not find user %s", senderName);
		return;
	    }
	    if (sender->level < LEVEL_MODERATOR)
	    {
		log ("muzzle(): %s has no privilege", sender->nick);
		return;		/* no permission */
	    }
	}
    }
    else
    {
	sender = con->user;
	senderName = sender->nick;
    }

    if (pkt)
	ac = split_line (av, FIELDS (av), pkt);

    if (ac < 1)
    {
	log ("muzzle(): too few parameters");
	print_args (ac, av);
	unparsable (con);
	return;
    }

    /* find the user to be muzzled.  user may not be currently logged in. */
    user = hash_lookup (Users, av[0]);

    /* look up this entry in the user db.  may not be registered. */
    db = hash_lookup (User_Db, av[0]);

    /* check for privilege to execute */
    if (sender && sender->level < LEVEL_ELITE &&
	((user && user->level >= sender->level) ||
	 (db && db->level >= sender->level)))
    {
	permission_denied (con);
	return;
    }

    /* can't register a nick without them being online */
    /* TODO: this could be a problem if the user dbs are out of sync among
       linked servers since in that case you really should propogate the
       message since it could be registered elsewhere */
    if (!db && !user)
    {
	nosuchuser(con);
	return;
    }

    if (ac>1)
	truncate_reason(av[1]);

    if (tag == MSG_CLIENT_MUZZLE)
    {
	if (!db)
	{
	    /* force registration */
	    log ("muzzle(): forcing registration for %s", user->nick);
	    db = create_db(user);
	}
	if ((user && user->muzzled) || (db && (db->flags & ON_MUZZLED)))
	{
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH, "%s is already muzzled",
			  user ? user->nick : db->nick);
	    return;
	}
	if (user)
	    user->muzzled = 1;
	if (db)			/*malloc could have failed */
	    db->flags |= ON_MUZZLED;
    }
    else
    {
	ASSERT (tag == MSG_CLIENT_UNMUZZLE);
	if ((user && !user->muzzled) || !db || (!(db->flags & ON_MUZZLED)))
	{
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH, "%s is not muzzled", av[0]);
	    return;
	}
	if (user)
	    user->muzzled = 0;
	/* if we set muzzled, it should have been registered */
	ASSERT (db != 0);
	db->flags &= ~ON_MUZZLED;
    }

    /* relay to peer servers */
    pass_message_args (con, tag, ":%s %s \"%s\"", senderName, av[0],
		       (ac > 1) ? av[1] : "");

    /* notify the user they have been muzzled */
    if (user && ISUSER (user->con))
	send_cmd (user->con, MSG_SERVER_NOSUCH,
		  "You have been %smuzzled%s%s: %s",
		  (tag == MSG_CLIENT_MUZZLE) ? "" : "un",
		  sender && sender->cloaked ? "" : " by ",
		  sender && sender->cloaked ? "" : senderName,
		  (ac > 1) ? av[1] : "");

    /* notify mods+ of this action */
    notify_mods (MUZZLELOG_MODE, "%s has %smuzzled %s: %s",
		 senderName,
		 (tag == MSG_CLIENT_MUZZLE) ? "" : "un",
		 av[0], (ac > 1) ? av[1] : "");
}
