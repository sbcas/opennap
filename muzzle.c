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

    if (tag == MSG_CLIENT_MUZZLE)
    {
	if (!db)
	{
	    /* can't register a nick without them being online */
	    if (!user)
	    {
		if (ISUSER (con))
		{
		    send_cmd (con, MSG_SERVER_NOSUCH, "%s is not registered",
			      av[0]);
		}
		return;
	    }
	    /* force registration */
	    log ("muzzle(): forcing registration for %s", user->nick);
	    db = CALLOC (1, sizeof (USERDB));
	    if (db)
	    {
		db->nick = STRDUP (user->nick);
		db->password = generate_pass (user->pass);
		snprintf (Buf, sizeof (Buf), "anon@%s", Server_Name);
		db->email = STRDUP (Buf);
		db->level = user->level;
		db->created = Current_Time;
		db->lastSeen = Current_Time;
		if (db->nick && db->password && db->email)
		{
		    if (hash_add (User_Db, db->nick, db))
			userdb_free (db);
		}
		else
		{
		    OUTOFMEMORY ("muzzle");
		    userdb_free (db);
		}
	    }
	    else
		OUTOFMEMORY ("muzzle");
	}
	if ((user && user->muzzled) || (db && (db->flags & ON_MUZZLED)))
	{
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH, "%s is already muzzled",
			  user->nick);
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
