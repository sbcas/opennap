/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
#include "opennap.h"
#include "debug.h"

/* change the user level for a user */
/* [ :<nick> ] <user> <level> */
HANDLER (level)
{
    char *sender = 0, *fields[2];
    USER *user;
    int level;
    USERDB *db;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    /* NOTE: we implicity trust that messages we receive from other servers
       are authentic, so we don't check the user privileges here.  we have
       to trust that the peer servers perform due dilegence before sending
       a message to us, otherwise we could never propogate initial user
       levels across all servers */
    if (ISSERVER (con))
    {
	/* skip over who set the user level */
	if (*pkt != ':')
	{
	    log ("level(): server message was missing colon prefix");
	    return;
	}
	pkt++;
	sender = next_arg (&pkt);
	if (!pkt)
	{
	    log ("level(): request contained too few fields");
	    return;
	}
    }

    if (split_line (fields, sizeof (fields) / sizeof (char *), pkt) != 2)
    {
	log ("level(): malformed client request");
	return;
    }

    user = hash_lookup (Users, fields[0]);
    if (!user)
    {
	if (ISUSER (con))
	    nosuchuser (con, fields[0]);
	log ("level(): user synch error, can't locate user %s", fields[0]);
	return;
    }

    ASSERT (validate_user (user));

    if ((level = get_level (fields[1])) == -1)
    {
	log ("level(): tried to set %s to unknown level %s",
	     user->nick, fields[1]);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "no such level as %s",
		      fields[1]);
	return;
    }

    /* check for privilege */
    if (ISUSER (con))
    {
	ASSERT (validate_user (con->user));
	if ((level >= con->user->level && con->user->level < LEVEL_ELITE) ||
	    user->level >= con->user->level)
	{
	    log ("level(): %s tried to set %s to level %s", con->user->nick,
		 user->nick, Levels[level]);
	    permission_denied (con);
	    return;
	}
	sender = con->user->nick;
    }

    if (Num_Servers)
	pass_message_args (con, MSG_CLIENT_SETUSERLEVEL, ":%s %s %s",
			   sender, user->nick, Levels[level]);

    notify_mods ("%s set %s's user level to %s (%d).", sender, user->nick,
		 Levels[level], level);

    /* we set this after the notify_mods so that the user being changed
       doesnt get notified twice */
    user->level = level;

    if (user->local)
    {
	/* notify the user of their change in status */
	send_cmd (user->con, MSG_SERVER_NOSUCH,
		  "%s changed your level to %s (%d).",
		  sender, Levels[user->level], user->level);
    }

    log ("level(): %s set %s's level to %s", sender, user->nick,
	 Levels[user->level]);

    /* if this is a registered nick, update our db so this change is
       persistent */
    db = userdb_fetch (user->nick);
    if (db)
    {
	db->level = level;
	if (userdb_store (db))
	    log ("level(): userdb_store failed (ignored)");
	else
	    log ("level(): updated level in user database");
	userdb_free (db);
    }
    else if (user->level > LEVEL_USER)
    {
	char email[64];

	/* no local user db entry.  this nick probably should be registered */
	log ("level(): %s is not locally registered, creating entry");
	db = CALLOC (1, sizeof (USERDB));
	if (!db)
	{
	    OUTOFMEMORY ("level");
	    return;
	}
	db->nick = user->nick;
	db->password = user->pass;
	db->level = user->level;
	if (user->email)
	    db->email = user->email;
	else
	{
	    snprintf (email, sizeof (email), "anon@%s", Server_Name);
	    db->email = email;
	}
	/* we use the current time.  this should be ok since if we ever try
	   to propogate this entry the server(s) with older entries will
	   override this one and update our entry */
	db->created = Current_Time;
	db->lastSeen = Current_Time;
	if (userdb_store (db))
	    log ("level(): userdb_store failed");
	FREE (db);
    }
}
