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

int
invalid_nick (const char *s)
{
    int count = 0;

    /* don't allow anyone to ever have this nick */
    if (!strcasecmp (s, "operserv") || !strcasecmp (s, "chanserv") ||
	!strcasecmp (s, "operator"))
	return 1;
    while (*s)
    {
	if (!ISPRINT (*s) || ISSPACE (*s) || *s == ':' || *s == '%'
	    || *s == '$')
	    return 1;
	count++;
	s++;
    }
    /* enforce min/max nick length */
    return (count == 0 || (Max_Nick_Length > 0 && count > Max_Nick_Length));
}

static void
sync_reginfo (USERDB * db)
{
    log ("sync_reginfo(): sending registration info to peers");
    pass_message_args (NULL, MSG_SERVER_REGINFO,
		       ":%s %s %s %s %s %d %d", Server_Name,
		       db->nick, db->password,
#if EMAIL
		       db->email,
#else
		       "unknown",
#endif
		       Levels[db->level], db->timestamp, db->lastSeen);
}

/* generic function to generate a kill for a user */
static void
kill_client (const char *nick, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;

    va_start (ap, fmt);
    vsnprintf (buf, sizeof (buf), fmt, ap);
    va_end (ap);

    pass_message_args (NULL, MSG_CLIENT_KILL, ":%s %s \"%s\"", Server_Name,
		       nick, buf);
    notify_mods (KILLLOG_MODE, "%s killed %s: %s", Server_Name, nick, buf);
}

static void
zap_local_user (CONNECTION * con, const char *reason)
{
    ASSERT (validate_connection (con));
    ASSERT (ISUSER (con));
    ASSERT (reason != NULL);

    /* TODO: there is a numeric for this somewhere */
    send_cmd (con, MSG_SERVER_NOSUCH, "You were killed by %s: %s",
	      Server_Name, reason);
    con->killed = 1;		/* dont generate a QUIT message */
    remove_user (con);
    /* avoid free'g con->user in remove_connection().  do
       this here to avoid the ASSERT() in remove_user() */
    con->class = CLASS_UNKNOWN;
    con->uopt = 0;		/* just to be safe since it was free'd */
    con->user = 0;
    con->destroy = 1;
}

/* 2 <nick> <pass> <port> <client-info> <speed> [email] [build]

   servers append some additional information that they need to share in
   order to link:

   2 <nick> <pass> <port> <client-info> <speed> <email> <ts> <ip> <server> <serverport>

   <ts> is the time at which the client logged in (timestamp)
   <ip> is the client's ip address
   <server> is the server they are connected to
   <port> is the remote port on the server they are connected to */
HANDLER (login)
{
    char *av[10];
    USER *user;
    HOTLIST *hotlist;
    int ac, speed, port;
    USERDB *db = 0;

    (void) len;
    ASSERT (validate_connection (con));

    if (ISUSER (con))
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "you are already logged in");
	return;
    }

    ac = split_line (av, FIELDS (av), pkt);

    /* check for the correct number of fields for this message type.  some
       clients send extra fields, so we just check to make sure we have
       enough for what is required in this implementation. */
    if (ac < 5)
    {
	log ("login(): too few parameters (tag=%d)", tag);
	print_args (ac, av);
	if (ISUNKNOWN (con))
	{
	    unparsable (con);
	    con->destroy = 1;
	}
	return;
    }

    if (invalid_nick (av[0]))
    {
	if (ISUNKNOWN (con))
	{
	    send_cmd (con, MSG_SERVER_BAD_NICK, "");
	    con->destroy = 1;
	}
	else
	{
	    ASSERT (ISSERVER (con));
	    kill_client (av[0], "invalid nick");
	}
	return;
    }

    /* retrieve registration info (could be NULL) */
    db = hash_lookup (User_Db, av[0]);

    /* enforce maximum local users.  if the user is privileged, bypass
     * this restriction */
    if (ISUNKNOWN (con) && Num_Clients >= Max_Connections &&
	(!db || db->level < LEVEL_MODERATOR))
    {
	log ("login(): max_connections (%d) reached", Max_Connections);
	send_cmd (con, MSG_SERVER_ERROR,
		  "This server is full (%d connections)", Max_Connections);
	con->destroy = 1;
	return;
    }

    /* check for user|ip ban.  mods+ are exempt */
    if (!db || db->level < LEVEL_MODERATOR)
    {
	if (check_ban (con, av[0]))
	    return;
    }

    speed = atoi (av[4]);
    if (speed < 0 || speed > 10)
    {
	if (ISUNKNOWN (con))
	{
	    send_cmd (con, MSG_SERVER_ERROR, "invalid speed");
	    con->destroy = 1;
	    return;
	}
	ASSERT(ISSERVER(con));
	notify_mods(ERROR_MODE,"Invalid speed %d for user %s from server %s",
		    speed, av[0], con->host);
	log ("login(): invalid speed %d received from server %s",
	     speed, con->host);
	/* set to something sane.  this is only informational so its not
	   a big deal if we are out of synch */
	speed = 0;
    }

    port = atoi (av[2]);
    if (port < 0 || port > 65535)
    {
	if (ISUNKNOWN (con))
	{
	    send_cmd (con, MSG_SERVER_ERROR, "invalid port");
	    con->destroy = 1;
	    return;
	}
	ASSERT(ISSERVER(con));
	notify_mods(ERROR_MODE,"Invalid port %d for user %s from server %s",
		    port, av[0], con->host);
	log ("login(): invalid port %d received from server %s",
	     port, con->host);
	port = 0;
	/* TODO: generate a change port command */
    }

    if (tag == MSG_CLIENT_LOGIN)
    {
	if (db == NULL)
	{
	    if (Server_Flags & ON_REGISTERED_ONLY)
	    {
		send_cmd (con, MSG_SERVER_ERROR,
			  "only registered accounts allowed on this server");
		con->destroy = 1;
		return;
	    }
	    if (Server_Flags & ON_AUTO_REGISTER)
		tag = MSG_CLIENT_LOGIN_REGISTER;
	}
    }

    if (tag == MSG_CLIENT_LOGIN_REGISTER)
    {
	/* check to see if the account is already registered */
	if (db)
	{
	    if (ISUNKNOWN (con))
	    {
		/* this could happen if two clients simultaneously connect
		   and register */
		send_cmd (con, MSG_SERVER_ERROR,
			  "account registered to another user");
		con->destroy = 1;
	    }
	    else
	    {
		ASSERT (ISSERVER (con));
		/* need to issue a kill and send the registration info
		   we have on this server */
		kill_client (av[0], "account registered to another user");
		sync_reginfo (db);
	    }
	    return;
	}
	/* else, delay creating db until after we make sure the nick is
	   not currently in use */
    }
    else if (db)
    {
	ASSERT (tag == MSG_CLIENT_LOGIN);
	/* check the user's password */
	if (check_pass (db->password, av[1]))
	{
	    if (db->level > LEVEL_USER)
	    {
		/* warn about privileged users */
		notify_mods (ERROR_MODE, "Bad password for %s (%s) from %s",
			     db->nick, Levels[db->level], my_ntoa (con->ip));
		pass_message_args (NULL, MSG_SERVER_NOTIFY_MODS,
				   ":%s %d \"Bad password for %s (%s) from %s\"",
				   Server_Name, ERROR_MODE,
				   db->nick, Levels[db->level],
				   my_ntoa (con->ip));
	    }
	    if (ISUNKNOWN (con))
	    {
		send_cmd (con, MSG_SERVER_ERROR, "Invalid Password");
		con->destroy = 1;
	    }
	    else
	    {
		ASSERT (ISSERVER (con));
		/* if another server let this message pass through, that
		   means they probably have an out of date password.  notify
		   our peers of the registration info.  note that it could be
		   _this_ server that is stale, but when the other servers
		   receive this message they will check the creation date and
		   send back any entries which are more current that this one.
		   kind of icky, but its the best we can do */
		kill_client (av[0], "invalid password");
		sync_reginfo (db);
	    }
	    return;
	}
    }

    /* check to make sure that this user isn't ready logged in. */
    if ((user = hash_lookup (Users, av[0])))
    {
	ASSERT (validate_user (user));

	if (ISUNKNOWN (con))
	{
	    /* check for ghosts.  if another client from the same ip address
	       logs in, kill the older client and proceed normally */
	    if (user->host == con->ip)
	    {
		kill_client (user->nick, "ghost (%s)", user->server);
		/* remove the old entry */
		if (ISUSER (user->con))
		    zap_local_user (user->con, "ghost");
		else
		    hash_remove (Users, user->nick);
	    }
	    else
	    {
		send_cmd (con, MSG_SERVER_ERROR, "%s is already active",
			  user->nick);
		con->destroy = 1;
		return;
	    }
	}
	else
	{
	    ASSERT (ISSERVER (con));
	    if(ac>=10)
	    {
		/* check the timestamp to see which client is older.  the last
		   one to connect gets killed. when the timestamp is not
		   available, both clients are killed. */
		if (atoi (av[6]) < user->connected)
		{
		    /* reject the client that was already logged in since has
		     an older timestamp */

		    /* the user we see logged in after the same user on another
		       server, so we want to kill the existing user.  we don't
		       pass this back to the server that we received the login
		       from because that will kill the legitimate user */
		    pass_message_args (con, MSG_CLIENT_KILL,
			    ":%s %s \"nick collision (%s %s)\"",
			    Server_Name, user->nick, av[8], user->server);
		    notify_mods (KILLLOG_MODE,
			    "%s killed %s: nick collision (%s %s)",
			    Server_Name, user->nick, av[8], user->server);

		    if (ISUSER (user->con))
			zap_local_user (user->con, "nick collision");
		    else
			hash_remove (Users, user->nick);
		    /* proceed with login normally */
		}
		else
		{
		    /* the client we already know about is older, reject
		       this login */
		    log("login(): nick collision for user %s, rejected login from server %s", con->host);
		    return;
		}
	    }
	    else
	    {
		/* no timestamp available, reject both clients */
		notify_mods (KILLLOG_MODE,
			"%s killed %s: nick collision (no TS from %s)",
			Server_Name, user->nick, con->host);
		/* notify other servers of the kill. we don't send the kill
		   to the server we received the login request from */
		pass_message_args(con,MSG_CLIENT_KILL,
			":%s %s \"nick collision (no TS from %s)\"",
			Server_Name,user->nick,con->host);
		if(ISUSER(user->con))
		{
		    user->con->killed = 1;
		    user->con->destroy = 1;
		    send_cmd(user->con, MSG_SERVER_NOSUCH,
			    "You were killed by %s: nick collision",
			    Server_Name);
		}
		else
		    hash_remove(Users,user->nick);
		return;
	    }
	}
    }

    if (tag == MSG_CLIENT_LOGIN_REGISTER)
    {
	/* create the registration entry now */
	ASSERT (db == 0);
	db = CALLOC (1, sizeof (USERDB));
	if (db)
	{
	    db->nick = STRDUP (av[0]);
	    db->password = generate_pass (av[1]);
#if EMAIL
	    if (ac > 5)
		db->email = STRDUP (av[5]);
	    else
	    {
		snprintf (Buf, sizeof (Buf), "anon@%s", Server_Name);
		db->email = STRDUP (Buf);
	    }
#endif
	}
	if (!db || !db->nick || !db->password
#if EMAIL
	    || !db->email
#endif
	    )
	{
	    OUTOFMEMORY ("login");
	    if (con->class == CLASS_UNKNOWN)
		con->destroy = 1;
	    userdb_free (db);
	    return;
	}
	db->level = LEVEL_USER;
	db->timestamp = Current_Time;
	if (hash_add (User_Db, db->nick, db))
	{
	    log ("login(): hash_add failed (ignored)");
	    userdb_free (db);
	    db = NULL;
	}
    }

    user = new_user();
    if (user)
    {
	user->nick = STRDUP (av[0]);
	/* if the client version string is too long, truncate it */
	if (Max_Client_String > 0
	    && strlen (av[3]) > (unsigned) Max_Client_String)
	    *(av[3] + Max_Client_String) = 0;
	user->clientinfo = STRDUP (av[3]);
	user->pass = STRDUP (av[1]);
    }
    if (!user || !user->nick || !user->clientinfo || !user->pass)
    {
	OUTOFMEMORY ("login");
	goto failed;
    }
    user->port = port;
    user->speed = speed;
    user->con = con;
    user->level = LEVEL_USER;	/* default */

    /* if this is a locally connected user, update our information */
    if (ISUNKNOWN (con))
    {
	/* save the ip address of this client */
	user->connected = Current_Time;
	user->local = 1;
	user->host = con->ip;
	user->conport = con->port;
	if (!(user->server = STRDUP (Server_Name)))
	{
	    OUTOFMEMORY ("login");
	    goto failed;
	}
	con->uopt = CALLOC (1, sizeof (USEROPT));
	if (!con->uopt)
	{
	    OUTOFMEMORY ("login");
	    goto failed;
	}
	con->uopt->usermode = LOGALL_MODE;
	con->user = user;
	con->class = CLASS_USER;
	/* send the login ack */
#if EMAIL
	if (db)
	    send_cmd (con, MSG_SERVER_EMAIL, "%s", db->email);
	else
#endif
	    send_cmd (con, MSG_SERVER_EMAIL, "anon@%s", Server_Name);
	show_motd (con, 0, 0, NULL);
	server_stats (con, 0, 0, NULL);
    }
    else
    {
	ASSERT (ISSERVER (con));
	/* newer servers (0.33+) pass the additional information in the
	   login message, check for it here */
	if (ac >= 10)
	{
	    /* data is present */
	    user->connected = atoi (av[6]);
	    user->host = atoi (av[7]);
	    user->server = STRDUP (av[8]);
	    if (!user->server)
	    {
		OUTOFMEMORY ("login");
		goto failed;
	    }
	    user->conport = atoi (av[9]);
	}
	else
	    user->connected = Current_Time; /* TS not present */
    }

    if (hash_add (Users, user->nick, user))
    {
	log ("login(): hash_add failed (fatal)");
	goto failed;
    }

    /* pass this information to our peer servers */
    if (Servers)
    {
	/*  if we have full information, use the new method */
	if ((ISSERVER (con) && ac >= 10) || ISUSER (con))
	    pass_message_args (con, MSG_CLIENT_LOGIN,
			       "%s %s %s \"%s\" %s %s %d %u %s %hu",
			       av[0], av[1], av[2], av[3], av[4],
#if EMAIL
			       db ? db->email : "unknown",
#else
			       "unknown",
#endif /* EMAIL */
			       user->connected, user->host, user->server,
			       user->conport);
	else
	    pass_message_args (con, MSG_CLIENT_LOGIN, "%s %s %s \"%s\" %s",
			       av[0], av[1], av[2], av[3], av[4]);

	/* TODO: the following goes away once everyone is upgraded */
#if 1
	/* only generate this message for local users */
	if (ISUSER (con))
	    pass_message_args (con, MSG_SERVER_USER_IP, "%s %u %hu %s",
			       user->nick, user->host, user->conport,
			       Server_Name);
#endif
    }

    if (db)
    {
	db->lastSeen = Current_Time;

	/* this must come after the email ack or the win client gets confused */
	if (db->level != LEVEL_USER)
	{
	    /* do this before setting the user level so this user is not
	       notified twice */
	    notify_mods (LEVELLOG_MODE, "%s set %s's user level to %s (%d)",
			 Server_Name, user->nick, Levels[db->level],
			 db->level);
	    user->level = db->level;
	    if (ISUSER (con))
	    {
		/* notify users of their change in level */
		send_cmd (con, MSG_SERVER_NOSUCH,
			  "%s set your user level to %s (%d).",
			  Server_Name, Levels[user->level], user->level);
	    }
	    /* ensure all servers are synched up.  use the timestamp here
	       so that multiple servers all end up with the same value if
	       they differ */
	    pass_message_args (NULL, MSG_CLIENT_SETUSERLEVEL, ":%s %s %s %d",
			       Server_Name, user->nick, Levels[user->level],
			       db->timestamp);
	}

	if (db->flags & ON_MUZZLED)
	{
	    /* user was muzzled when they quit, remuzzle */
	    user->muzzled = 1;
	    /* this will result in duplicate messages for the same user from
	       each server, but its the only way to guarantee that the user
	       is muzzled upon login */
	    pass_message_args (NULL, MSG_CLIENT_MUZZLE,
			       ":%s %s \"quit while muzzled\"",
			       Server_Name, user->nick);
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH,
			  "You have been muzzled by %s: quit while muzzled",
			  Server_Name);
	    notify_mods (MUZZLELOG_MODE,
			 "%s has muzzled %s: quit while muzzled", Server_Name,
			 user->nick);
	}

	if (db->flags & ON_CLOAKED)
	{
	    /* dont use the cloak() handler function since that will just
	       toggle the value and we need to absolutely turn it on in
	       this case in order to make sure the servers all synch up */
	    ASSERT (user->level > LEVEL_USER);
	    user->cloaked = 1;
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH, "You are now cloaked.");
	    notify_mods (CHANGELOG_MODE, "%s has cloaked", user->nick);
	    /* use the absolute version of the command to make sure its
	       not toggled if servers differ */
	    pass_message_args (NULL, MSG_CLIENT_CLOAK, ":%s 1", user->nick);
	}
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
    if (!ISSERVER (con))
	con->destroy = 1;
    if (user)
    {
	if (user->nick)
	    FREE (user->nick);
	if (user->clientinfo)
	    FREE (user->clientinfo);
	if (user->pass)
	    FREE (user->pass);
	if (user->server)
	    FREE (user->server);
	mp_free (UserPool, user);
    }
}

/* 10013 <user> <ip> <port> <server>
   peer server is sending us the ip address for a locally connected client
   TODO: this message goes away once everyone is upgraded */
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
    if (!ISUSER (user->con))
    {
	pass_message_args (con, tag, "%s %s %s %s", user->nick,
			   field[1], field[2], field[3]);
	if (user->server)
	    return;		/* already have it from the new login(2) message */
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
    if ((db = hash_lookup (User_Db, pkt)))
    {
	send_cmd (con, MSG_SERVER_REGISTER_FAIL, "");
	return;
    }
    if (invalid_nick (pkt))
	send_cmd (con, MSG_SERVER_BAD_NICK, "");
    else
	send_cmd (con, MSG_SERVER_REGISTER_OK, "");
}

/* 10114 :<server> <nick> <password> <level> <email> <timestamp> <lastseen> */
HANDLER (reginfo)
{
    char *server;
    char *fields[6];
    USERDB *db;
    int level;

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
    db = hash_lookup (User_Db, pkt);
    if (db)
    {
	/* check the timestamp to see if this is more recent than what
	   we have */
	if (atol (fields[4]) > db->timestamp)
	{
	    /* our record was created first, notify peers */
	    log ("reginfo(): stale reginfo received from %s", server);
	    sync_reginfo (db);
	    return;
	}
	/* update our record */
	FREE (db->password);
#if EMAIL
	FREE (db->email);
#endif
    }
    else
    {
	if (invalid_nick (fields[0]))
	{
	    log ("reginfo(): received invalid nickname");
	    return;
	}
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
	hash_add (User_Db, db->nick, db);
    }
    level = get_level (fields[3]);
    if (level == -1)
    {
	log ("reginfo(): invalid level %s", fields[3]);
	level = LEVEL_USER;	/* reset to something reasonable */
    }

    pass_message_args (con, tag, ":%s %s %s %s %s %s %s",
		       server, fields[0], fields[1], fields[2], Levels[level],
		       fields[4], fields[5]);

    /* this is already the MD5-hashed password, just copy it */
    db->password = STRDUP (fields[1]);
#if EMAIL
    db->email = STRDUP (fields[2]);
#endif
    if (!db->password
#if EMAIL
	|| !db->email
#endif
	)
    {
	OUTOFMEMORY ("reginfo");
	return;
    }
    db->level = level;
    db->timestamp = atol (fields[4]);
    db->lastSeen = atol (fields[5]);
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
	permission_denied (con);
	return;
    }
    ac = split_line (av, sizeof (av) / sizeof (char *), pkt);

    if (ac < 3)
    {
	unparsable (con);
	return;
    }
    if (invalid_nick (av[0]))
    {
	invalid_nick_msg (con);
	return;
    }
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
	    permission_denied (con);
	    return;
	}
    }
    else
	level = LEVEL_USER;	/* default */

    /* first check to make sure this user is not already registered */
    if (hash_lookup (User_Db, av[0]))
    {
	send_user (sender, MSG_SERVER_NOSUCH, "[%s] %s is already registered",
		   Server_Name, av[0]);
	return;
    }
    /* pass the plain text password here */
    pass_message_args (con, tag, ":%s %s %s %s %s",
		       sender->nick, av[0], av[1], av[2],
		       ac > 3 ? av[3] : "");

    db = CALLOC (1, sizeof (USERDB));
    if (!db)
    {
	OUTOFMEMORY ("register_user");
	return;
    }
    db->nick = STRDUP (av[0]);
    db->password = generate_pass (av[1]);
#if EMAIL
    db->email = STRDUP (av[2]);
#endif
    if (!db->nick || !db->password
#if EMAIL
	|| !db->email
#endif
	)
    {
	OUTOFMEMORY ("register_user");
	FREE (db);
	return;
    }
    db->level = level;
    db->timestamp = Current_Time;
    db->lastSeen = Current_Time;
    hash_add (User_Db, db->nick, db);

    notify_mods (CHANGELOG_MODE, "%s registered nickname %s (%s)",
		 sender->nick, db->nick, Levels[db->level]);
}

/* 11 <user> <password>
   check password */
HANDLER (check_password)
{
    char *nick;
    USERDB *db;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    ASSERT (con->class == CLASS_UNKNOWN);
    nick = next_arg (&pkt);
    if (!pkt)
    {
	unparsable (con);
	return;
    }
    db = hash_lookup (User_Db, nick);
    if (db)
    {
	if (!check_pass (db->password, pkt))
	    send_cmd (con, MSG_SERVER_PASS_OK, "");
    }
}

/* 300 <port>
   check client data port */
HANDLER (check_port)
{
    ASSERT (validate_connection (con));
    (void) tag;
    (void) len;
    (void) pkt;
    (void) con;
    /* just ignore this message for now */
}
