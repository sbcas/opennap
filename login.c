/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <mysql.h>
#include <arpa/inet.h>
#include "opennap.h"
#include "debug.h"

extern MYSQL *Db;

/* packet contains: <nick> <pass> <port> <client-info> <speed> [ <email> ] */
HANDLER (login)
{
    char *field[6];
    USER *user;
    HOTLIST *hotlist;

    ASSERT (VALID (con));

    if (split_line (field, sizeof (field) / sizeof (char *), pkt) < 5)
    {
	log ("login(): too few fields in message");
	return;
    }

    /* check to make sure that this user isn't ready logged in */
    user = hash_lookup (Users, field[0]);
    if (user)
    {
	/* user already exists */
	ASSERT (VALID (user));

	if (con->class == CLASS_UNKNOWN)
	{
	    log ("login(): user %s is already active", user->nick);
	    remove_connection (con);
	}
	else
	{
	    ASSERT (con->class == CLASS_SERVER);

	    log ("login(): nick collision detected for user %s", user->nick);

	    /* issue a KILL for this user if we have one of them locally
	       connected */
	    if (user->con)
	    {
		/* pass this message to everyone */
		pass_message_args (NULL, MSG_CLIENT_KILL, ":%s %s",
				   Server_Name, user->nick);
		/* destroy the connection */
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

    user = CALLOC (1, sizeof (USER));
    user->nick = STRDUP (field[0]);
    user->port = atoi (field[2]);
    user->clientinfo = STRDUP (field[3]);
    user->speed = atoi (field[4]);
    user->connected = time (0);

    hash_add (Users, user->nick, user);

    /* if this is a locally connected user, update our information */
    if (con->class == CLASS_UNKNOWN)
    {
	/* save the ip address of this client */
	user->host = inet_addr (con->host);

	/* pass this information to our peer servers */
	if (Num_Servers)
	{
	    pass_message_args (con, MSG_CLIENT_LOGIN, "%s %s %s \"%s\" %s",
		    field[0], field[1], field[2], field[3], field[4]);
	    pass_message_args (con, MSG_SERVER_USER_IP, "%s %lu",
		    field[0], user->host);
	}

	con->class = CLASS_USER;
	con->user = user;
	user->con = con;

	/* ack the login - we don't really keep track of email addresses,
	   so fake it the way that napster does */
	send_cmd (con, MSG_SERVER_EMAIL, "anon@%s", Server_Name);

	show_motd (con);
	server_stats (con, NULL);

	/* query our local accounts database for mod/admin privileges */
	snprintf (Buf, sizeof (Buf),
		  "SELECT * FROM accounts WHERE nick = '%s'", user->nick);
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
			    log ("login(): bad password for user %s", user->nick);
			    remove_connection (con);
			}
			else
			{
			    if (strcasecmp ("admin", row[2]) == 0)
				user->flags |= FLAG_ADMIN;
			    else if (strcasecmp ("moderator", row[2]) == 0)
				user->flags |= FLAG_MODERATOR;
			    log ("login(): setting %s to level %s", user->nick,
				    (user->flags & FLAG_ADMIN) ? "admin" :
				    "moderator");

			    /* broadcast the updated userlevel to our peer
			       servers */
			    if ((user->flags & (FLAG_ADMIN | FLAG_MODERATOR)) != 0
				    && Num_Servers)
			    {
				pass_message_args (con, MSG_CLIENT_SETUSERLEVEL,
					":%s %s %s", Server_Name,
					user->nick,
					(user->flags & FLAG_ADMIN) ?
					"admin" : "moderator");
			    }
			}
		    }
		    break;
		default:
		    log ("login(): query returned >1 rows!");
		    remove_connection (con);
		    break;
	    }

	    mysql_free_result (result);
	}
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

/* 10013 <user> <ip> */
/* peer server is sending us the ip address for a locally connected client */
HANDLER (user_ip)
{
    char *field[2];
    USER *user;

    ASSERT (VALID (con));
    CHECK_SERVER_CLASS ("user_ip");
    if(split_line(field,sizeof(field)/sizeof(char*),pkt)!=2)
    {
	log("user_ip(): wrong number of arguments");
	return;
    }
    user=hash_lookup(Users,field[0]);
    if(!user)
    {
	log("user_ip(): could not find struct for %s", field[0]);
	return;
    }
    user->host = strtoul (field[1], 0, 10);
}
