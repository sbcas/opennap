/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdlib.h>
#include <string.h>
#include "opennap.h"
#include "debug.h"

/* user request to change the data port they are listening on.
   703 [ :<user> ] <port> */
HANDLER (change_data_port)
{
    int port;
    USER *user;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &user) != 0)
	return;
    ASSERT (validate_user (user));
    port = atoi (pkt);

    /* the official server doesn't seem to check the value sent, so this
       error is unique to this implementation */
    if (port >= 0 && port <= 65535)
    {
	user->port = port;
	pass_message_args (con, tag, ":%s %d", user->nick, user->port);
    }
    else if (ISUSER (con))
	send_cmd (con, MSG_SERVER_NOSUCH, "invalid data port");
}

/* 700 [ :<user> ] <speed> */
/* client is changing link speed */
HANDLER (change_speed)
{
    USER *user;
    int spd;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &user) != 0)
	return;
    spd = atoi (pkt);
    if (spd >= 0 && spd <= 10)
    {
	user->speed = spd;
	pass_message_args (con, tag, ":%s %d", user->nick, spd);
    }
    else if (ISUSER (con))
	send_cmd (con, MSG_SERVER_NOSUCH, "invalid speed");
}

/* 701 [ :<user> ] <password>
   change user password */
HANDLER (change_pass)
{
    USER *user;
    USERDB *db;

    (void) tag;
    (void) len;
    if (pop_user (con, &pkt, &user) != 0)
	return;
    if (!pkt || !*pkt)
    {
	log ("change_pass(): missing new password");
	unparsable (con);
	return;
    }
    /* pass this along even if it is not locally registered.  the user db
     * is distributed so a record for it may reside on another server */
    pass_message_args (con, tag, ":%s %s", user->nick, pkt);
    db = hash_lookup (User_Db, user->nick);
    if (!db)
    {
	log ("change_pass(): %s is not registered", user->nick);
	return;
    }
    FREE (db->password);
    db->password = generate_pass (pkt);
    db->timestamp = Current_Time;
    if (ISUSER (con))
	send_cmd (con, MSG_SERVER_NOSUCH, "password changed");
}

/* 702 [ :<user> ] <email>
   change email address */
HANDLER (change_email)
{
#if EMAIL
    USER *user;
    USERDB *db;

    (void) tag;
    (void) len;
    if (pop_user (con, &pkt, &user) != 0)
	return;
    if (!pkt || !*pkt)
    {
	log ("change_email(): missing new email address");
	unparsable (con);
	return;
    }
    pass_message_args (con, tag, ":%s %s", user->nick, pkt);
    db = hash_lookup (User_Db, user->nick);
    if (!db)
    {
	log ("change_email(): could not find user %s in the database",
	     user->nick);
	return;
    }
    FREE (db->email);
    db->email = STRDUP (pkt);
    db->timestamp = Current_Time;
#else
    (void)tag;
    (void)len;
    (void)pkt;
    (void)con;
#endif
}

/* 613 [ :<sender> ] <user> <port> [ <reason> ]
   admin request to change a user's data port */
HANDLER (alter_port)
{
    USER *sender, *user;
    char *nick, *port;
    int p;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &sender) != 0)
	return;
    /* check for privilege */
    if (sender->level < LEVEL_MODERATOR)
    {
	log ("alter_port(): %s has no privilege to change ports",
	     sender->nick);
	permission_denied (con);
	return;
    }

    nick = next_arg (&pkt);
    port = next_arg (&pkt);
    if (!nick || !port)
    {
	unparsable (con);
	return;
    }
    user = hash_lookup (Users, nick);
    if (!user)
    {
	nosuchuser (con);
	return;
    }
    p = atoi (port);
    if (p < 0 || p > 65535)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "%d is an invalid port", p);
	return;
    }

    if(pkt)
	truncate_reason(pkt);

    if (user->port != p)
    {
	/* only log when the port value is actually changed, not resets */
	notify_mods (CHANGELOG_MODE, "%s changed %s's data port to %d: %s",
		     sender->nick, user->nick, p, NONULL (pkt));
	user->port = p;
    }

    /* if local user, send them the message */
    if (user->local)
	send_cmd (user->con, MSG_CLIENT_ALTER_PORT, "%d", p);

    pass_message_args (con, tag, ":%s %s %d", sender->nick, user->nick, p);

    log ("alter_port(): %s set %s's data port to %d", sender->nick,
	 user->nick, p);
}

/* 753 [ :<sender> ] <nick> <pass> "<reason>"
   admin command to change a user's password */
HANDLER (alter_pass)
{
    USER *sender;
    int ac;
    char *av[3];
    USERDB *db;

    ASSERT (validate_connection);
    (void) tag;
    (void) len;
    if (pop_user (con, &pkt, &sender))
	return;
    if (sender->level < LEVEL_ADMIN)
    {
	permission_denied (con);
	return;
    }
    if (!pkt)
    {
	unparsable (con);
	return;
    }
    ac = split_line (av, sizeof (av) / sizeof (char *), pkt);

    if (ac != 3)
    {
	log ("alter_pass(): wrong number of arguments");
	print_args (ac, av);
	unparsable (con);
	return;
    }
    if (invalid_nick (av[0]))
    {
	invalid_nick_msg(con);
	return;
    }
    truncate_reason(av[2]);
    /* send this now since the account might not be locally registered */
    pass_message_args (con, tag, ":%s %s %s \"%s\"", sender->nick, av[0],
		       av[1], av[2]);
    db = hash_lookup (User_Db, av[0]);
    if (db)
    {
	char *newpass;

	newpass = generate_pass (av[1]);
	if (!newpass)
	{
	    OUTOFMEMORY ("alter_pass");
	    return;
	}
	FREE (db->password);
	db->password = newpass;
	db->timestamp = Current_Time;
    }
    notify_mods (CHANGELOG_MODE, "%s changed %s's password: %s",
		 sender->nick, av[0], av[2]);
}

/* 625 [ :<sender> ] <nick> <speed>
   admin command to change another user's reported line speed */
HANDLER (alter_speed)
{
    USER *sender, *user;
    int ac, speed;
    char *av[2];

    ASSERT (validate_connection (con));
    (void) len;
    if (pop_user (con, &pkt, &sender))
	return;
    ac = split_line (av, sizeof (av) / sizeof (char *), pkt);

    if (ac < 2)
    {
	unparsable (con);
	return;
    }
    if (sender->level < LEVEL_MODERATOR)
    {
	permission_denied (con);
	return;
    }
    speed = atoi (av[1]);
    if (speed < 0 || speed > 10)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "Invalid speed");
	return;
    }
    user = hash_lookup (Users, av[0]);
    if (!user)
    {
	nosuchuser (con);
	return;
    }
    ASSERT (validate_user (user));
    if (user->speed == speed)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "%s's speed is already %d",
		      user->nick, speed);
	return;
    }
    user->speed = speed;
    pass_message_args (con, tag, ":%s %s %d", sender->nick, user->nick,
		       speed);
    notify_mods (CHANGELOG_MODE, "%s changed %s's speed to %d.",
		 sender->nick, user->nick, speed);
}

/* 611 [ :<sender> ] <user> [ <reason> ]
   nuke a user's account */
HANDLER (nuke)
{
    USER *sender;
    USERDB *db;
    char *nick;

    ASSERT (validate_connection (con));
    (void) len;
    if (pop_user (con, &pkt, &sender))
	return;
    if (sender->level < LEVEL_MODERATOR)
    {
	if (ISUSER (con))
	    permission_denied (con);
	return;
    }
    nick = next_arg (&pkt);
    if (!nick)
    {
	unparsable (con);
	return;
    }
    if (invalid_nick (nick))
    {
	invalid_nick_msg(con);
	return;
    }
    if(pkt)
	truncate_reason(pkt);
    /* pass the message in case its not locally registered */
    pass_message_args (con, tag, ":%s %s %s", sender->nick, nick,
		       NONULL (pkt));
    db = hash_lookup (User_Db, nick);
    if (db)
    {
	if (sender->level < LEVEL_ELITE && sender->level <= db->level)
	{
	    permission_denied (con);
	    return;
	}
	hash_remove (User_Db, db->nick);
    }
    notify_mods (CHANGELOG_MODE, "%s nuked %s's account: %s",
	    sender->nick, nick, NONULL (pkt));
}

#if 0
/* 624 [ :<sender> ] <user>
   un-nuke a user's account */
HANDLER (unnuke)
{
    USER *sender;
    USERDB *db;

    ASSERT (validate_connection (con));
    (void) len;
    if (pop_user (con, &pkt, &sender))
	return;
    if (sender->level < LEVEL_MODERATOR)
    {
	permission_denied (con);
	return;
    }
    if (!pkt)
    {
	ASSERT (ISSERVER (con));
	log ("unnuke(): missing user name");
	return;
    }
    db = hash_lookup (User_Db, pkt);
    if (!db)
    {
	log ("unnuke(): %s is not registered", pkt);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "%s is not registered", pkt);
	return;
    }
    if (sender->level <= db->level)
    {
	log ("unnuke(): %s has no privilege to unnuke %s's account",
	     sender->nick, pkt);
	if (ISUSER (con))
	    permission_denied (con);
	return;
    }
    db->nuked = 0;
    pass_message_args (con, tag, ":%s %s", sender->nick, pkt);
    notify_mods (CHANGELOG_MODE, "%s restored %s's account",
		 sender->nick, pkt);
}
#endif

/* 652 [ :<sender> [1] ]
   toggle the invisible state of the current user.  when a server is the
   sender of the message, the 1 signifies that the cloak status should
   absolutely be turned on rather than toggled (used for synch) */
HANDLER (cloak)
{
    USER *sender;
    USERDB *db;

    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &sender))
	return;
    if (sender->level < LEVEL_MODERATOR)
    {
	permission_denied (con);
	return;
    }
    /* check for absolute cloak (synch) */
    if(ISSERVER(con) && pkt && atoi(pkt) == 1 && sender->cloaked)
	return; /* already cloaked */
    sender->cloaked = !sender->cloaked;	/* toggle cloak state */
    /* save cloak state in the user db */
    db = hash_lookup (User_Db, sender->nick);
    if (!db)
    {
	log ("cloak(): FATAL ERROR, moderator not registered???");
	return;
    }
    if (sender->cloaked)
	db->flags |= ON_CLOAKED;
    else
	db->flags &= ~ON_CLOAKED;
    db->timestamp = Current_Time;
    pass_message_args (con, tag, ":%s", sender->nick);
    notify_mods (CLOAKLOG_MODE, "%s has %scloaked", sender->nick,
		 sender->cloaked ? "" : "de");
    if (ISUSER (con))
	send_cmd (con, MSG_SERVER_NOSUCH, "You are %s cloaked.",
		  sender->cloaked ? "now" : "no longer");
}
