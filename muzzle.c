/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
#include <stdio.h>
#include "opennap.h"
#include "debug.h"

/* [ :<nick> ] <user-to-muzzle> [ "<reason>" ] */
HANDLER (muzzle)
{
    USER *user;
    char *av[2], *sender;
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
	sender = next_arg (&pkt);
    }
    else
	sender = con->user->nick;

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
	nosuchuser (con, av[0]);
	return;
    }
    ASSERT (validate_user (user));

    /* if a local user issued this command, check for privilege to execute */
    if (ISUSER (con) && con->user->level < LEVEL_ELITE &&
	user->level >= con->user->level)
    {
	permission_denied (con);
	return;
    }

    if (user->muzzled)
    {
	log ("muzzle(): %s is already muzzled", user->nick);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "%s is already muzzled",
		      user->nick);
	return;
    }

    /* relay to peer servers */
    if (ac > 1)
	pass_message_args (con, tag, ":%s %s \"%s\"", sender, user->nick,
			   av[1]);
    else
	pass_message_args (con, tag, ":%s %s", sender, user->nick);

    user->muzzled = 1;

    db = hash_lookup (User_Db, user->nick);
    if (!db)
    {
	log ("muzzle(): forcing registration of user %s", user->nick);
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
    if (db)			/* could be NULL if we ran out of memory */
	db->muzzled = 1;

    /* notify the user they have been muzzled */
    if (user->local)
	send_cmd (user->con, MSG_SERVER_NOSUCH,
		  "You have been muzzled by %s: %s", sender,
		  ac > 1 ? av[1] : "");

    /* notify mods+ of this action */
    notify_mods (MUZZLELOG_MODE, "%s has muzzled %s: %s", sender,
		 user->nick, ac > 1 ? av[1] : "");
}
