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
    pass_message_args (con, tag, "%s", pkt);
    db = userdb_fetch (user->nick);
    if (!db)
    {
	log ("change_pass(): could not find user %s in the database",
	     user->nick);
	return;
    }
    FREE (db->password);
    db->password = STRDUP (pkt);
    if (userdb_store (db))
	log ("change_pass(): userdb_store failed");
    userdb_free (db);
}

/* 702 [ :<user> ] <email>
   change email address */
HANDLER (change_email)
{
    USER *user;
    USERDB *db;

    (void) tag;
    (void) len;
    if (pop_user (con, &pkt, &user) != 0)
	return;
    pass_message_args (con, tag, "%s", pkt);
    db = userdb_fetch (user->nick);
    if (!db)
    {
	log ("change_email(): could not find user %s in the database",
	     user->nick);
	return;
    }
    FREE (db->email);
    db->email = STRDUP (pkt);
    if (userdb_store (db))
	log ("change_email(): userdb_store failed");
    userdb_free (db);
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
	if (con->class == CLASS_USER)
	    permission_denied (con);
	return;
    }

    nick = next_arg (&pkt);
    port = next_arg (&pkt);
    if (!nick || !port)
    {
	log ("alter_port(): too few arguments");
	if (con->class == CLASS_USER)
	    send_cmd (con, MSG_SERVER_NOSUCH, "too few arguments");
	return;
    }
    user = hash_lookup (Users, nick);
    if (!user)
    {
	log ("alter_port(): no such user %s", nick);
	if (con->class == CLASS_USER)
	    nosuchuser (con, nick);
	return;
    }
    p = atoi (port);
    if (p < 0 || p > 65535)
    {
	log ("alter_port(): %d is an invalid port", p);
	if (con->class == CLASS_USER)
	    send_cmd (con, MSG_SERVER_NOSUCH, "%s is an invalid port", p);
	return;
    }
    user->port = p;

    /* if local user, send them the message */
    if (user->local)
	send_cmd (user->con, MSG_CLIENT_ALTER_PORT, "%d", p);

    pass_message_args (con, tag, ":%s %s %d", sender->nick, user->nick, p);

    notify_mods ("%s changed %s's data port to %d: %s", sender->nick,
		 user->nick, p, NONULL (pkt));
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
	log ("alter_pass(): %s has no privilege", sender->nick);
	if (ISUSER (con))
	    permission_denied (con);
	return;
    }
    if (!pkt)
    {
	log ("alter_pass(): missing arguments");
	return;
    }
    ac = split_line (av, sizeof (av) / sizeof (char *), pkt);

    if (ac != 3)
    {
	log ("alter_pass(): wrong number of arguments");
	print_args (ac, av);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "Wrong number of arguments.");
	return;
    }
    db = userdb_fetch (av[0]);
    if (!db)
    {
	log ("alter_pass(): %s is not registered", av[0]);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "%s is not a registered nick.",
		      av[0]);
	return;
    }
    FREE (db->password);
    db->password = STRDUP (av[1]);
    if (!db->password)
    {
	OUTOFMEMORY ("alter_pass");
	userdb_free (db);
	return;
    }
    pass_message_args (con, tag, ":%s %s %s \"%s\"", sender->nick, db->nick,
		       db->password, av[2]);
    notify_mods ("%s changed %s's password: %s", sender->nick, db->nick,
		 av[2]);
    if (userdb_store (db))
    {
	log ("alter_pass(): userdb_store failed");
	send_user (sender, MSG_SERVER_NOSUCH, "[%s] db failure", Server_Name);
    }
    userdb_free (db);
}

/* 625 [ :<sender> ] <nick> <speed>
   admin command to change another user's reported line speed */
HANDLER (alter_speed)
{
    USER *sender, *user;
    int ac, speed;
    char *av[2];

    ASSERT (validate_connection (con));
    (void) tag;
    (void) len;
    if (pop_user (con, &pkt, &sender))
	return;
    ac = split_line (av, sizeof (av) / sizeof (char *), pkt);

    if (ac != 2)
    {
	log ("alter_speed(): wrong number of parameters");
	print_args (ac, av);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "Wrong number of parameters");
	return;
    }
    if (sender->level < LEVEL_MODERATOR)
    {
	if (ISUSER (con))
	    permission_denied (con);
	return;
    }
    speed = atoi (av[1]);
    if (speed < 0 || speed > 10)
    {
	log ("alter_speed(): invalid speed %d", speed);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "Invalid speed.");
	return;
    }
    user = hash_lookup (Users, av[0]);
    if (!user)
    {
	log ("alter_speed(): could not find %s", av[0]);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH,
		      "User %s is not currently online.", av[0]);
	return;
    }
    ASSERT (validate_user (user));
    pass_message_args (con, tag, ":%s %s %d", sender->nick, user->nick,
		       speed);
    notify_mods ("%s changed %s's speed to %d.", sender->nick, user->nick,
		 speed);
}
