/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "opennap.h"
#include "debug.h"

/* change the user level for a user */
/* [ :<nick> ] <user> <level> */
HANDLER (level)
{
    char *sender = 0, *fields[2];
    USER *user;
    int level, ac;
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

    if ((ac = split_line (fields, FIELDS (fields), pkt)) != 2)
    {
	log ("level(): malformed client request");
	print_args (ac, fields);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "wrong number of parameters");
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
	    send_cmd (con, MSG_SERVER_NOSUCH, "%s: invalid level", fields[1]);
	return;
    }
    if (user->level == level)
    {
	log ("level(): %s is already level %s", user->nick, Levels[level]);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "%s is already level %s.",
		    user->nick, Levels[level]);
	return;
    }
    /* check for privilege */
    if (ISUSER (con))
    {
	ASSERT (validate_user (con->user));
	if (con->user->level < LEVEL_ELITE &&
	    /* don't allow change to a higher level than the issuer */
	    (level >= con->user->level ||
	     /* allow users to change themself to a lower level */
	     (con->user != user && user->level >= con->user->level)))
	{
	    log ("level(): %s tried to set %s to level %s", con->user->nick,
		user->nick, Levels[level]);
	    permission_denied (con);
	    return;
	}
	sender = con->user->nick;
    }

    /* relay to peer servers */
    pass_message_args (con, MSG_CLIENT_SETUSERLEVEL, ":%s %s %s",
		       sender, user->nick, Levels[level]);

    notify_mods (LEVELLOG_MODE, "%s set %s's user level to %s (%d).", sender, user->nick,
		 Levels[level], level);

    /* we set this after the notify_mods so that the user being changed
       doesnt get notified twice */
    user->level = level;

    if (user->local)
    {
	/* notify the user of their change in status */
	send_cmd (user->con, MSG_SERVER_NOSUCH,
		  "%s changed your user level to %s (%d).",
		  sender, Levels[user->level], user->level);
    }

    log ("level(): %s set %s's user level to %s", sender, user->nick,
	 Levels[user->level]);

    /* if this is a registered nick, update our db so this change is
       persistent */
    db = hash_lookup (User_Db, user->nick);
    if (db)
    {
	log ("level(): updated level in user database");
	db->level = level;
    }
    else
    {
	char email[64];

	/* no local user db entry.  this nick probably should be registered */
	log ("level(): %s is not registered, creating entry", user->nick);
	db = CALLOC (1, sizeof (USERDB));
	if (!db)
	{
	    OUTOFMEMORY ("level");
	    return;
	}
	db->nick = STRDUP (user->nick);
	db->password = generate_pass (user->pass);
	db->level = user->level;
	if (user->email)
	    db->email = STRDUP (user->email);
	else
	{
	    snprintf (email, sizeof (email), "anon@%s", Server_Name);
	    db->email = STRDUP (email);
	}
	/* we use the current time.  this should be ok since if we ever try
	   to propogate this entry the server(s) with older entries will
	   override this one and update our entry */
	db->created = Current_Time;
	db->lastSeen = Current_Time;
	hash_add (User_Db, db->nick, db);
    }
}
