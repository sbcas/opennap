/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "opennap.h"
#include "debug.h"

/* [ :<nick> ] <user> <level> [timestamp]
   change the user level for a user */
HANDLER (level)
{
    char *sender, *av[3];
    USER *user, *senderUser=0;
    int level, ac;
    USERDB *db;

    (void) len;
    ASSERT (validate_connection (con));

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
	if (!is_server(sender))
	{
	    senderUser=hash_lookup(Users,sender);
	    if(!senderUser)
		log("level(): could not find user %s", sender);
	}
    }
    else
    {
	sender = con->user->nick;
	senderUser = con->user;
    }

    if ((ac = split_line (av, FIELDS (av), pkt)) < 2)
    {
	log ("level(): malformed request");
	print_args (ac, av);
	unparsable (con);
	return;
    }

    if ((level = get_level (av[1])) == -1)
    {
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

    /* check to see if the user is registered */
    db = hash_lookup (User_Db, av[0]);

    /* if the level is already correct, just ignore it */
    if (db && db->level == level)
    {
	if(ISUSER(con))
	    send_cmd(con,MSG_SERVER_NOSUCH,"user %s is already level %s",
		     db->nick, Levels[db->level]);
	return;
    }

    /* check to see if the user is logged in */
    user = hash_lookup (Users, av[0]);

    /* if the level is already correct, just ignore it */
    if (user && user->level == level)
    {
	ASSERT(level==LEVEL_USER);
	if(ISUSER(con))
	    send_cmd(con,MSG_SERVER_NOSUCH,"user %s is already level %s",
		     user->nick, Levels[user->level]);
	return;
    }

    if (!db)
    {
	if (user)
	{
	    /* create db entry based on logged in user */
	    db = create_db (user);
	    if(!db)
		return;
	}
	else
	{
	    log("level(): unable to register account for %s", av[0]);
	    if(ISUSER(con))
		send_cmd(con,MSG_SERVER_NOSUCH,"user is is not registered");
	    return;
	}
    }

    ASSERT(db!=0);

    /* if the server sent a timestamp, check it now */
    if (ISSERVER(con) && ac>2)
    {
	time_t ts = atoi(av[2]);
	if(ts>db->timestamp)
	{
	    log("level(): TS for %s is newer", db->nick);
	    return;
	}
	else if(ts==db->timestamp)
	{
	    /* TODO: handle this case */
	    log("level(): ERROR: TS is equal but value is different");
	}
    }

    /* check for permission, allow self-demotion */
    if (senderUser && senderUser != user && senderUser->level < LEVEL_ELITE &&
	senderUser->level <= db->level)
    {
	permission_denied(con);
	return;
    }

    /* update the db entry */
    db->level = level;
    db->timestamp = Current_Time;
    /* non-mod+ users can't decloak so make sure they are not cloaked */
    if(level < LEVEL_MODERATOR && (db->flags & ON_CLOAKED))
	db->flags &= ~ON_CLOAKED;

    pass_message_args (con, tag, ":%s %s %s", sender, db->nick, Levels[level]);

    /* notify now so the user doesnt get notified twice when going from
       user to mod+ */
    notify_mods (LEVELLOG_MODE, "%s changed %s's user level to %s (%d)",
		 sender, db->nick, Levels[level], level);

    /* if the user is currently logged in, change their level now */
    if (user)
    {
	if(ISUSER(user->con))
	    send_cmd (user->con, MSG_SERVER_NOSUCH,
		      "%s changed your user level to %s (%d)",
		      (senderUser && senderUser->cloaked && level < LEVEL_MODERATOR) ? "Operator" : sender,
		      Levels[level], level);

	user->level = level;
	/* non-mod+ users can't decloak so make sure they are not cloaked */
	if(level < LEVEL_MODERATOR && user->cloaked)
	{
	    user->cloaked = 0;
	    notify_mods (CHANGELOG_MODE, "%s has decloaked", user->nick);
	    if(ISUSER(user->con))
		send_cmd(user->con,MSG_SERVER_NOSUCH,"You are no longer cloaked.");
	}
    }
}
