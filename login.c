/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <mysql.h>
#include "opennap.h"
#include "debug.h"

extern MYSQL *Db;

/* packet contains: <nick> <pass> <port> <client-info> <speed> [ <email> ] */
HANDLER (login)
{
    char *field[6];
    USER *user;
    HOTLIST *hotlist;
    int i, numfields, speed;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    numfields = split_line (field, sizeof (field) / sizeof (char *), pkt);
    if (numfields < 5)
    {
	log ("login(): too few fields in message");
	return;
    }
    speed = atoi (field[4]);
    if (speed < 0 || speed > 10)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "%d is an invalid speed.", speed);
	return;
    }

    /* check to make sure that this user isn't ready logged in */
    user = hash_lookup (Users, field[0]);
    if (user)
    {
	/* user already exists */
	ASSERT (validate_user (user));

	if (con->class == CLASS_UNKNOWN)
	{
	    log ("login: user %s is already active", user->nick);
	    send_cmd (con, MSG_SERVER_ERROR, "user %s is already active",
		user->nick);
	    con->destroy = 1;
	}
	else
	{
	    ASSERT (con->class == CLASS_SERVER);

	    log ("login: nick collision detected for user %s", user->nick);

	    /* issue a KILL for this user if we have one of them locally
	       connected */
	    if (user->con)
	    {
		/* pass this message to everyone */
		pass_message_args (NULL, MSG_CLIENT_KILL, ":%s %s",
				   Server_Name, user->nick);
		/* destroy the connection - ok to remove it here since
		   con != user->con in this case */
		remove_connection (user->con);
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
	if (Ban[i]->type == BAN_USER && !strcasecmp (field[0], Ban[i]->target))
	{
	    log ("login(): banned user %s tried to log in", field[0]);
	    if (con->class == CLASS_UNKNOWN)
	    {
		send_cmd (con, MSG_SERVER_NOSUCH,
			"You are banned from this server: %s",
			NONULL (Ban[i]->reason));
		con->destroy = 1;
	    }
	    notify_mods ("Banned user %s attempted to log in", field[0]);
	    return;
	}

    user = new_user ();
    user->nick = STRDUP (field[0]);
    user->port = atoi (field[2]);
    user->clientinfo = STRDUP (field[3]);
    user->speed = speed;
    user->connected = time (0);
    user->level = LEVEL_USER;
    if (numfields > 5)
	user->email = STRDUP (field[5]);

    hash_add (Users, user->nick, user);

    /* if this is a locally connected user, update our information */
    if (con->class == CLASS_UNKNOWN)
    {
	/* save the ip address of this client */
	user->host = con->ip;
	/* user->conport = con->port; */
	user->server = STRDUP (Server_Name);

	/* pass this information to our peer servers */
	if (Num_Servers)
	{
	    pass_message_args (con, MSG_CLIENT_LOGIN, "%s %s %s \"%s\" %s",
		    field[0], field[1], field[2], field[3], field[4]);
	    pass_message_args (con, MSG_SERVER_USER_IP, "%s %lu %hu %s",
		    field[0], user->host, user->conport, Server_Name);
	}

	con->class = CLASS_USER;
	con->user = user;
	user->con = con;

	/* query our local accounts database for mod/admin privileges */
	snprintf (Buf, sizeof (Buf),
		  "SELECT * FROM accounts WHERE nick LIKE '%s'", user->nick);
	if (mysql_query (Db, Buf) != 0)
	{
	    sql_error ("login", Buf);
	    /* not fatal */
	}
	else
	{
	    MYSQL_RES *result = mysql_store_result (Db);

	    switch (mysql_num_rows (result))
	    {
		case 0:
		    break;		/* no entry, proceed normally */
		case 1:
		    {
			MYSQL_ROW row = mysql_fetch_row (result);

			/* verify the password */
			if (strcmp (field[1], row[1]) != 0)
			{
			    log ("login(): bad password for user %s",
				user->nick);
			    send_cmd (con, MSG_SERVER_NOSUCH,
				"invalid password");
			    con->destroy = 1;
			    mysql_free_result (result);
			    return;
			}
			else
			{
			    if (!strcasecmp ("elite", row[2]))
				user->level = LEVEL_ELITE;
			    else if (!strcasecmp ("admin", row[2]))
				user->level = LEVEL_ADMIN;
			    else if (strcasecmp ("moderator", row[2]) == 0)
				user->level = LEVEL_MODERATOR;
			    else
			    {
				log ("login(): unknown level %s for %s in accounts table",
				    row[2], row[0]);
			    }
			    if (user->level > LEVEL_USER)
			    {
				/* broadcast the updated userlevel to our peer
				   servers */
				if (Num_Servers)
				    pass_message_args (con,
					MSG_CLIENT_SETUSERLEVEL,
					":%s %s %s", Server_Name,
					user->nick, row[2]);
				/* notify users of their change in level */
				send_cmd (con, MSG_SERVER_NOSUCH,
				    "server set your level to %s (%d).",
				    Levels[user->level], user->level);
			    }

			    log ("login(): set %s to level %s", user->nick,
				Levels[user->level]);
			}
		    }
		    break;
		default:
		    log ("login(): query returned >1 rows!");
		    send_cmd (con, MSG_SERVER_ERROR, "sql error");
		    con->destroy = 1;
		    break;
	    }

	    mysql_free_result (result);

	}

	/* ack the login - we don't really keep track of email addresses,
	   so fake it the way that napster does */
	send_cmd (con, MSG_SERVER_EMAIL, "anon@%s", Server_Name);
	show_motd (con);
	server_stats (con, 0, 0, NULL);
    }
    else
    {
	/* all we need to do here is store which connection this user is
	   behind.  this is needed so that if the server splits, we know
	   to remove this user from the global user list */
	ASSERT (con->class == CLASS_SERVER);
	user->serv = con;
    }

    /* check the global hotlist to see if there are any users waiting to be
       informed of this user signing on */
    hotlist = hash_lookup (Hotlist, user->nick);
    if (hotlist)
    {
	/* notify users */
	int i;

	ASSERT (hotlist->numusers > 0);
	for (i = 0; i < hotlist->numusers; i++)
	    send_cmd (hotlist->users[i], MSG_SERVER_USER_SIGNON, "%s %d",
		user->nick, user->speed);
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

    ASSERT (VALID (con));
    CHECK_SERVER_CLASS ("user_ip");
    if (split_line (field, sizeof (field) / sizeof (char* ), pkt) != 4)
    {
	log ("user_ip(): wrong number of arguments");
	return;
    }
    user = hash_lookup (Users, field[0]);
    if (!user)
    {
	log ("user_ip(): could not find struct for %s", field[0]);
	return;
    }
    user->host = strtoul (field[1], 0, 10);
    user->conport = strtoul (field[2], 0, 10);
    user->server = STRDUP (field[3]);
}
