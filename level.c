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
    char *sender, *fields[2];
    USER *user;
    int level, ac;
    USERDB *db;

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
    else
	sender = con->user->nick;

    if ((ac = split_line (fields, FIELDS (fields), pkt)) != 2)
    {
	log ("level(): malformed request");
	print_args (ac, fields);
	unparsable (con);
	return;
    }

    if ((level = get_level (fields[1])) == -1)
    {
	log ("level(): unknown level %s", fields[1]);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "invalid level");
	return;
    }

    /* dont allow a user to set another user to a level higher than their
       own */
    if (ISUSER (con) && con->user->level < LEVEL_ELITE &&
	level >= con->user->level)
    {
	permission_denied (con);
	return;
    }

    if ((user = hash_lookup (Users, fields[0])))
    {
	/* user is logged in */
	ASSERT (validate_user (user));
	if (ISUSER (con) && con->user->level < LEVEL_ELITE &&
	    con->user != user &&	/* allow self demotion */
	    user->level >= con->user->level)
	{
	    permission_denied (con);
	    return;
	}
	if (user->level == level)
	{
	    log ("level(): %s is already %s", user->nick, Levels[level]);
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH, "%s is already %s",
			  user->nick, Levels[level]);
	    return;
	}
	if (ISUSER (user->con))
	    send_cmd (user->con, MSG_SERVER_NOSUCH,
		      "%s changed your user level to %s (%d)",
		      sender, Levels[level], level);
	/* delay setting user->level until after the notify_mods() call so
	   that a user promoted to mod+ doesnt get notified twice */
    }

    if ((db = hash_lookup (User_Db, fields[0])))
    {
	/* registered nick */
	if (ISUSER (con) && con->user->level < LEVEL_ELITE &&
	    /* allow self demotion */
	    strcasecmp (con->user->nick, db->nick) != 0 &&
	    con->user->level <= db->level)
	{
	    ASSERT (user == 0);
	    permission_denied (con);
	    return;
	}
	if (db->level == level)
	{
	    ASSERT (user == 0 || user->level == db->level);
	    if (user)
		user->level = db->level;	/* just to be safe */
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH, "%s is already %s",
			  db->nick, Levels[level]);
	    return;
	}
	db->level = level;
	/* user can't decloak if they become unprivileged, so ensure we
	   are in a sane state */
	if (level < LEVEL_MODERATOR && (db->flags & ON_CLOAKED))
	{
	    db->flags &= ~ON_CLOAKED;
	    if (user)
	    {
		ASSERT (user->cloaked != 0);	/* should always be in sync */
		user->cloaked = 0;
		notify_mods (CHANGELOG_MODE, "%s has decloaked", user->nick);
	    }
	}
    }
    else if (user)
    {
	/* create a db entry for it now.  we already checked for permission
	   above so don't do it here */
	ASSERT (user->level == LEVEL_USER);
	db = CALLOC (1, sizeof (USERDB));
	if (db)
	{
	    db->nick = STRDUP (user->nick);
	    db->password = generate_pass (user->pass);
#if EMAIL
	    snprintf (Buf, sizeof (Buf), "anon@%s", Server_Name);
	    db->email = STRDUP (Buf);
#endif
	    db->level = level;
	    db->created = Current_Time;
	    db->lastSeen = Current_Time;
	}
	if (!db || !db->nick || !db->password
#if EMAIL
	    || !db->email
#endif
	    )
	{
	    OUTOFMEMORY ("level");
	    return;
	}
	if (hash_add (User_Db, db->nick, db))
	{
	    log ("level(): unable to add entry to hash table");
	    userdb_free (db);	/* avoid memory leak */
	}
    }
    else
    {
	/* if not linked, error out here.  if we are linked, the user could
	   be registered on another server so we just pass the request
	   along */
	if (!Servers)
	{
	    nosuchuser (con);
	    return;
	}
	if (invalid_nick (fields[0]))
	{
	    invalid_nick_msg(con);
	    return;
	}
    }

    pass_message_args (con, tag, ":%s %s %s", sender, fields[0],
		       Levels[level]);

    notify_mods (LEVELLOG_MODE, "%s changed %s's user level to %s (%d)",
		 sender, fields[0], Levels[level], level);

    /* we set this after the notify_mods so that the user being changed
       doesnt get notified twice */
    if (user)
	user->level = level;

    log ("level(): %s changed %s's user level to %s", sender, fields[0],
	 Levels[level]);
}
