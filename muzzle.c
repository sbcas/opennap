/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

/* [ :<nick> ] <user-to-muzzle> [ "<reason>" ] */
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
	if(!is_server(senderName))
	{
	    sender=hash_lookup(Users,senderName);
	    if(!sender)
	    {
		log("muzzle(): could not find user %s",senderName);
		return;
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

    /* find the user to be muzzled */
    user = hash_lookup (Users, av[0]);
    if (!user)
    {
	nosuchuser (con, av[0]);
	return;
    }
    ASSERT (validate_user (user));

    /* check for privilege to execute */
    if (sender && sender->level < LEVEL_ELITE && user->level >= sender->level)
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
    pass_message_args (con, tag, ":%s %s \"%s\"", senderName, user->nick,
			   (ac>1)?av[1]:"");

    user->muzzled = 1;

    /* store this permanently in the user db, forcing registration if the
       user is not already registered */
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
	db->flags |= ON_MUZZLED;

    /* notify the user they have been muzzled */
    if (user->local)
	send_cmd (user->con, MSG_SERVER_NOSUCH,
		  "You have been muzzled%s%s: %s",
		  sender&&sender->cloaked?"":" by ",
		  sender&&sender->cloaked?"":senderName,
		  ac > 1 ? av[1] : "");

    /* notify mods+ of this action */
    notify_mods (MUZZLELOG_MODE, "%s has muzzled %s: %s", senderName,
		 user->nick, ac > 1 ? av[1] : "");
}
