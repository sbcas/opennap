/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "opennap.h"
#include "debug.h"

static int
invalid_nick (const char *s)
{
    int count = 0;

    while (*s)
    {
	if (!ISPRINT (*s) || ISSPACE (*s) || *s == ':')
	    return 1;
	count++;
	s++;
    }
    /* enforce min/max nick length */
    return (count == 0 || (Max_Nick_Length > 0 && count > Max_Nick_Length));
}

static int
invalid_password (const char *s)
{
    int count = 0;

    for (; *s; s++, count++)
    {
	if (ISSPACE (*s))
	    return 1;
    }
    return ((count == 0));
}

static void
sync_reginfo (USERDB * db)
{
    log ("sync_reginfo(): sending registration info to peers");
    pass_message_args (NULL, MSG_SERVER_REGINFO,
		       ":%s %s %s %s %s %d %d", Server_Name,
		       db->nick, db->password, db->email,
		       Levels[db->level], db->created, db->lastSeen);
}

/* <nick> <pass> <port> <client-info> <speed> [ <email> ] */
HANDLER (login)
{
    char *av[7];
    USER *user;
    HOTLIST *hotlist;
    int i, ac, speed;
    USERDB *db = 0;

    (void) len;
    ASSERT (validate_connection (con));

    if (con->class == CLASS_USER)
    {
	log ("login(): recived command %d from a logged in user: %s", tag,
	     pkt);
	send_cmd (con, MSG_SERVER_NOSUCH, "you are already logged in");
	return;
    }

    ac = split_line (av, FIELDS (av), pkt);

    if ((tag == MSG_CLIENT_LOGIN && ac < 5) ||
	(tag == MSG_CLIENT_LOGIN_REGISTER && ac < 6))
    {
	log ("login(): too few avs in message (tag=%d)", tag);
	print_args (ac, av);
	if (con->class == CLASS_UNKNOWN)
	{
	    send_cmd (con, MSG_SERVER_ERROR, "Too few parameters for command");
	    con->destroy = 1;
	}
	return;
    }
    speed = atoi (av[4]);
    if (speed < 0 || speed > 10)
    {
	log ("login(): invalid speed %d from %s (%s)", speed, av[0], av[4]);
	if (con->class == CLASS_UNKNOWN)
	{
	    send_cmd (con, MSG_SERVER_ERROR, "%d is an invalid speed", speed);
	    con->destroy = 1;
	}
	return;
    }

    if (invalid_nick (av[0]))
    {
	log ("login(): invalid nick: %s", av[0]);
	if (con->class == CLASS_UNKNOWN)
	{
	    send_cmd (con, MSG_SERVER_BAD_NICK, "");
	    con->destroy = 1;
	}
	return;
    }

    /* a spurious newline in the password could cause corruption of the
       user database, so don't allow it.  if a user logged in as such:
       user baddpass\n"user realpass none elite 0 0"
       they could gain elite access on a server */
    if (invalid_password (av[0]))
    {
	log ("login(): password for %s contains invalid characters", av[0]);
	if (con->class == CLASS_UNKNOWN)
	    send_cmd (con, MSG_SERVER_ERROR,
		      "Your password contains illegal characters.");
	return;
    }

    /* check to make sure that this user isn't ready logged in */
    user = hash_lookup (Users, av[0]);
    if (user)
    {
	/* user already exists */
	ASSERT (validate_user (user));

	if (con->class == CLASS_UNKNOWN)
	{
	    log ("login(): user %s is already active", user->nick);
	    send_cmd (con, MSG_SERVER_ERROR, "user %s is already active",
		      user->nick);
	    con->destroy = 1;
	}
	else
	{
	    ASSERT (con->class == CLASS_SERVER);

	    log ("login(): nick collision for user %s", user->nick);

	    /* issue a KILL for this user if we have one of them locally
	       connected */
	    if (user->local)
	    {
		/* pass this message to everyone */
		pass_message_args (NULL, MSG_CLIENT_KILL,
				   ":%s %s \"nick collision\"", Server_Name,
				   user->nick);
		/* destroy the connection */
		user->con->destroy = 1;
	    }
	    else
	    {
		/* otherwise just remove this nick from our list.  we
		   don't send a KILL message because we would generate one
		   for each server, which is overkill */
		hash_remove (Users, user->nick);
	    }
	}
	return;
    }

    /* check for a user ban */
    for (i = 0; i < Ban_Size; i++)
	if (Ban[i]->type == BAN_USER && !strcasecmp (av[0], Ban[i]->target))
	{
	    log ("login(): banned user %s (%s) tried to log in", av[0],
		ISUSER (con) ? my_ntoa (con->ip) : "unknown");

	    if (con->class == CLASS_UNKNOWN)
	    {
		send_cmd (con, MSG_SERVER_NOSUCH,
			  "You are banned from this server: %s",
			  NONULL (Ban[i]->reason));
		con->destroy = 1;
	    }
	    notify_mods ("Banned user %s (%s) attempted to log in", av[0],
		ISUSER (con) ? my_ntoa (con->ip) : "unknown");
	    return;
	}

    user = new_user ();
    if (user)
    {
	user->nick = STRDUP (av[0]);
	user->clientinfo = STRDUP (av[3]);
	user->pass = STRDUP (av[1]);
    }
    if (!user || !user->nick || !user->clientinfo || !user->pass)
    {
	OUTOFMEMORY ("login");
	goto failed;
    }
    user->port = atoi (av[2]);
    user->speed = speed;
    user->connected = Current_Time;
    user->level = LEVEL_USER;	/* default */
    user->con = con;

    /* see if this is a registered nick */
    if ((db = userdb_fetch (av[0])))
    {
	/* yes, it is registered */
	if (tag == MSG_CLIENT_LOGIN_REGISTER)
	{
	    /* oops, its already registered */
	    log ("login(): %s is already registered", av[0]);
	    if (con->class == CLASS_UNKNOWN)
	    {
		/* this could happen if two clients simultaneously connect
		   and register */
		send_cmd (con, MSG_SERVER_ERROR, "%s is already registered.",
			av[0]);
	    }
	    else
	    {
		ASSERT (con->class == CLASS_SERVER);
		/* need to issue a kill and send the registration info
		   we have on this server */
		log ("login(): sending KILL for user %s", av[0]);
		pass_message_args (NULL, MSG_CLIENT_KILL,
				   ":%s %s \"account is already registered\"",
				   Server_Name, av[0]);
		sync_reginfo (db);
	    }
	    goto failed;
	}

	/* verify the password */
	if (strcmp (av[1], db->password) != 0)
	{
	    log ("login(): bad password for user %s", av[0]);
	    if (con->class == CLASS_UNKNOWN)
	    {
		send_cmd (con, MSG_SERVER_ERROR, "Invalid Password");
	    }
	    else
	    {
		ASSERT (con->class == CLASS_SERVER);
		/* if another server let this message pass through, that
		   means they probably have an out of date password.  notify
		   our peers of the registration info.  note that it could be
		   _this_ server that is stale, but when the other servers
		   receive this message they will check the creation date and
		   send back any entries which are more current that this one.
		   kind of icky, but its the best we can do */
		log ("login(): sending KILL for user %s", av[0]);
		pass_message_args (NULL, MSG_CLIENT_KILL,
				   ":%s %s \"invalid password\"", Server_Name,
				   av[0]);
		sync_reginfo (db);
	    }
	    goto failed;
	}

	/* update the last seen time */
	db->lastSeen = Current_Time;
	if (userdb_store (db))
	    log ("login(): userdb_store failed (ignored)");

	/* set the default userlevel */
	user->level = db->level;
	if (user->level != LEVEL_USER)
	{
	    log ("login(): set %s to level %s", user->nick,
		 Levels[user->level]);
	    notify_mods ("%s set %s's user level to %s (%d)", Server_Name,
		user->nick, Levels[user->level], level);
	}
    }
    else if (tag == MSG_CLIENT_LOGIN_REGISTER)
    {
	/* create the db entry now */
	log ("login(): registering user %s", av[0]);

	db = CALLOC (1, sizeof (USERDB));
	if (!db)
	{
	    OUTOFMEMORY ("login");
	    goto failed;
	}
	db->nick = STRDUP (av[0]);
	db->password = STRDUP (av[1]);
	db->email = STRDUP (av[5]);
	if (!db->nick || !db->password || !db->email)
	{
	    OUTOFMEMORY ("login");
	    goto failed;
	}
	db->level = LEVEL_USER;
	db->created = Current_Time;
	db->lastSeen = Current_Time;

	if (userdb_store (db))
	    log ("login(): userdb_store failed (ignored)");
    }

    if (hash_add (Users, user->nick, user))
    {
	log ("login(): hash_add failed (fatal)");
	goto failed;
    }

    /* if this is a locally connected user, update our information */
    if (con->class == CLASS_UNKNOWN)
    {
	/* save the ip address of this client */
	user->local = 1;
	user->host = con->ip;
	user->conport = con->port;
	if (!(user->server = STRDUP (Server_Name)))
	{
	    /* TODO: this is problematic.  we've already added the this
	       user struct to the global list and when we remove it,
	       free_user() will get called.  hopefully that will not
	       send messages to peer servers? */
	    OUTOFMEMORY ("login");
	    hash_remove (Users, user->nick);
	    goto failed;
	}
	con->class = CLASS_USER;
	con->user = user;
	/* send the login ack */
	if (db)
	    send_cmd (con, MSG_SERVER_EMAIL, db->email);
	else
	    send_cmd (con, MSG_SERVER_EMAIL, "anon@%s", Server_Name);
	show_motd (con, 0, 0, NULL);
	server_stats (con, 0, 0, NULL);

	/* we do this after sending the login/email ack (7) to avoid confusing
	   the win32 client */
	if (user->level != LEVEL_USER)
	{
	    /* notify users of their change in level */
	    send_cmd (con, MSG_SERVER_NOSUCH, "%s set your user level to %s (%d).",
		      Server_Name, Levels[user->level], user->level);
	}
    }

    if (db)
	userdb_free (db);

    /* pass this information to our peer servers */
    if (Servers)
    {
	pass_message_args (con, MSG_CLIENT_LOGIN, "%s %s %s \"%s\" %s",
			   av[0], av[1], av[2], av[3], av[4]);
	if (ISUSER (con))
	    pass_message_args (con, MSG_SERVER_USER_IP, "%s %u %hu %s",
			       av[0], user->host, user->conport, Server_Name);
	if (user->level != LEVEL_USER)
	    pass_message_args (con, MSG_CLIENT_SETUSERLEVEL,
			       ":%s %s %s", Server_Name, user->nick,
			       Levels[user->level]);
    }

    /* check the global hotlist to see if there are any users waiting to be
       informed of this user signing on */
    hotlist = hash_lookup (Hotlist, user->nick);
    if (hotlist)
    {
	/* notify users */
	LIST *u;

	ASSERT (validate_hotlist (hotlist));
	ASSERT (hotlist->users != 0);
	for (u = hotlist->users; u; u = u->next)
	{
	    ASSERT (validate_connection (u->data));
	    send_cmd (u->data, MSG_SERVER_USER_SIGNON, "%s %d",
		      user->nick, user->speed);
	}
    }
    return;

  failed:
    /* clean up anything we allocated here */
    if (con->class == CLASS_UNKNOWN)
	con->destroy = 1;
    if (db)
	userdb_free (db);
    if (user)
    {
	if (user->nick)
	    FREE (user->nick);
	if (user->email)
	    FREE (user->email);
	if (user->clientinfo)
	    FREE (user->clientinfo);
	if (user->pass)
	    FREE (user->pass);
	if (user->server)
	    FREE (user->server);
	if (user->files)
	    free_hash (user->files);
	FREE (user);
    }
}

/* 10013 <user> <ip> <port> <server> */
/* peer server is sending us the ip address for a locally connected client */
HANDLER (user_ip)
{
    char *field[4];
    USER *user;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_SERVER_CLASS ("user_ip");
    if (split_line (field, sizeof (field) / sizeof (char *), pkt) != 4)
    {
	log ("user_ip(): wrong number of arguments");
	return;
    }
    user = hash_lookup (Users, field[0]);
    if (!user)
    {
	log ("user_ip(): could not find %s", field[0]);
	return;
    }
    ASSERT (validate_user (user));
    if (!user->local)
    {
	pass_message_args (con, tag, "%s %s %s %s", user->nick,
		field[1], field[2], field[3]);
	user->host = strtoul (field[1], 0, 10);
	user->conport = atoi (field[2]);
	ASSERT (user->server == 0);
	if (!(user->server = STRDUP (field[3])))
	    OUTOFMEMORY ("user_ip");
    }
    else
    {
	/* nick collsion should have happened */
	ASSERT (con->destroy == 1);
	log ("user_ip(): ignoring info for local user (nick collision)");
    }
}

/* check to see if a nick is already registered */
/* 7 <nick> */
HANDLER (register_nick)
{
    USERDB *db;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (con->class != CLASS_UNKNOWN)
    {
	log ("register_nick(): command received after registration");
	send_cmd (con, MSG_SERVER_NOSUCH, "You are already logged in.");
	return;
    }
    log ("register_nick(): attempting to register %s", pkt);
    if ((db = userdb_fetch (pkt)))
    {
	userdb_free (db);
	log ("register_nick(): %s is already registered", pkt);
	send_cmd (con, MSG_SERVER_REGISTER_FAIL, "");
    }
    else
	send_cmd (con, MSG_SERVER_REGISTER_OK, "");
}

/* 10114 :<server> <nick> <password> <level> <email> <created> <lastseen> */
HANDLER (reginfo)
{
    char *server;
    char *fields[6];
    USERDB *db;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_SERVER_CLASS ("reginfo");

    if (*pkt != ':')
    {
	log ("reginfo(): message does not begin with :");
	return;
    }
    pkt++;
    server = next_arg (&pkt);
    if (!pkt)
    {
	log ("reginfo(): too few fields in message");
	return;
    }
    if (split_line (fields, sizeof (fields) / sizeof (char *), pkt) != 6)
    {
	log ("reginfo(): wrong number of fields");
	return;
    }
    /* look up any entry we have for this user */
    db = userdb_fetch (pkt);
    if (db)
    {
	/* check the timestamp to see if this is more recent than what
	   we have */
	if (atol (fields[4]) > db->created)
	{
	    /* our record was created first, notify peers */
	    log ("reginfo(): stale reginfo received from %s", server);
	    sync_reginfo (db);
	    return;
	}
	/* update our record */
	FREE (db->password);
	FREE (db->email);
    }
    else
    {
	db = CALLOC (1, sizeof (USERDB));
	if (db)
	    db->nick = STRDUP (fields[0]);
	if (!db || !db->nick)
	{
	    OUTOFMEMORY ("reginfo");
	    if (db)
		FREE (db);
	    return;
	}
    }

    pass_message_args (con, tag, ":%s %s %s %s %s %s %s",
		       server, fields[0], fields[1], fields[2], fields[3],
		       fields[4], fields[5]);

    db->password = STRDUP (fields[1]);
    db->email = STRDUP (fields[2]);
    if (!db->password || !db->email)
    {
	OUTOFMEMORY ("reginfo");
	userdb_free (db);
	return;
    }
    db->level = get_level (fields[3]);
    db->created = atol (fields[4]);
    db->lastSeen = atol (fields[5]);
    if (userdb_store (db))
	log ("reginfo(): userdb_store failed (ignored)");
    else
	log ("reginfo(): updated accounts table for %s", fields[0]);
    userdb_free (db);
}

/* 10200 [ :<sender> ] <user> <pass> <email> [ <level> ]
   admin command to force registration of a nickname */
HANDLER (register_user)
{
    USER *sender;
    int ac, level;
    char *av[4];
    USERDB *db;

    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &sender))
	return;
    if (sender->level < LEVEL_ADMIN)
    {
	log ("register_user(): %s has no privilege", sender->nick);
	if (ISUSER (con))
	    permission_denied (con);
	return;
    }
    ac = split_line (av, sizeof (av) / sizeof (char *), pkt);

    /* if the user level was specified do some security checks */
    if (ac > 3)
    {
	level = get_level (av[3]);
	/* check for a valid level */
	if (level == -1)
	{
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH, "Invalid level");
	    return;
	}
	/* check that the user has permission to create a user of this level */
	if (sender->level < LEVEL_ELITE && level >= sender->level)
	{
	    log ("register_user(): %s has no privilege to create %s accounts",
		 sender->nick, Levels[level]);
	    if (ISUSER (con))
		permission_denied (con);
	    return;
	}
    }
    else
	level = LEVEL_USER;	/* default */

    /* first check to make sure this user is not already registered */
    if (userdb_fetch (av[0]))
    {
	log ("register_user(): %s is already registered", av[0]);
	send_user (sender, MSG_SERVER_NOSUCH, "[%s] %s is already registered",
		   Server_Name, av[0]);
	return;
    }
    pass_message_args (con, tag, ":%s %s %s %s %s",
		       sender->nick, av[0], av[1], av[2],
		       ac > 3 ? av[3] : "");

    db = CALLOC (1, sizeof (USERDB));
    if (!db)
    {
	OUTOFMEMORY ("register_user");
	return;
    }
    db->nick = av[0];
    db->password = av[1];
    db->email = av[2];
    db->level = level;
    db->created = Current_Time;
    db->lastSeen = Current_Time;
    if (userdb_store (db))
    {
	log ("register_user(): userdb_store failed");
	send_user (sender, MSG_SERVER_NOSUCH,
		   "[%s] unable to register nick (db failure)", Server_Name);
    }
    FREE (db);
}
