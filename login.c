/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
#else
#include <windows.h>
#endif
#include <mysql.h>
#include <ctype.h>
#include "opennap.h"
#include "debug.h"

extern MYSQL *Db;

static int
invalid_nick (const char *s)
{
    while (*s)
    {
	if (*s & 0x80 || isspace (*s) || iscntrl (*s) || !isprint(*s) ||
		*s == ':')
	    return 1;
	s++;
    }
    return 0;
}

/* <nick> <pass> <port> <client-info> <speed> [ <email> ] */
HANDLER (login)
{
    char *field[7];
    USER *user;
    HOTLIST *hotlist;
    int i, n, numfields, speed;
    MYSQL_RES *result;
    MYSQL_ROW row = 0;
    LEVEL level = LEVEL_USER;

    (void) len;
    ASSERT (validate_connection (con));

    if (con->class == CLASS_USER)
    {
	log ("login(): recived command %d from a logged in user: %s", tag,
		pkt);
	send_cmd (con, MSG_SERVER_NOSUCH, "you are already logged in");
	return;
    }

    numfields = split_line (field, sizeof (field) / sizeof (char *), pkt);
    if (numfields < 5)
    {
	log ("login(): too few fields in message");
	if (con->class ==  CLASS_UNKNOWN)
	{
	    send_cmd (con, MSG_SERVER_ERROR, "too few fields for login command");
	    con->destroy = 1;
	}
	return;
    }
    speed = atoi (field[4]);
    if (speed < 0 || speed > 10)
    {
	log ("login(): invalid speed %d from %s (%s)",
		speed, field[0], field[4]);
	if (con->class == CLASS_UNKNOWN)
	{
	    send_cmd (con, MSG_SERVER_ERROR, "%d is an invalid speed", speed);
	    con->destroy = 1;
	}
	return;
    }

    if (invalid_nick (field[0]))
    {
	log ("login(): invalid nick: %s", field[0]);
	if (con->class == CLASS_UNKNOWN)
	{
	    send_cmd (con, MSG_SERVER_BAD_NICK, "");
	    con->destroy = 1;
	}
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

    /* see if this is a registered nick */
    snprintf (Buf, sizeof (Buf), "SELECT * FROM accounts WHERE nick='%s'",
	    field[0]);
    if (mysql_query (Db, Buf) != 0)
    {
	if (con->class == CLASS_UNKNOWN)
	{
	    send_cmd (con, MSG_SERVER_ERROR, "db error");
	    con->destroy = 1;
	}
	sql_error ("login", Buf);
	return;
    }
    result = mysql_store_result (Db);
    n = mysql_num_rows (result);
    if (n > 0)
    {
	/* yes, it is registered, fetch info */
	row = mysql_fetch_row (result);

	if (tag == MSG_CLIENT_LOGIN_REGISTER)
	{
	    /* oops, its already registered */
	    if (con->class == CLASS_UNKNOWN)
	    {
		/* this could happen if two clients simultaneously connect
		   and register */
		log ("login(): %s is already registered", field[0]);

		send_cmd (con, MSG_SERVER_ERROR,
			"that name is already registered");
		con->destroy = 1;
	    }
	    else
	    {
		ASSERT (con->class == CLASS_SERVER);
		/* need to issue a kill and send the registration info
		   we have on this server */
		log ("login(): registration request for %s, already registered here",
			row[0]);
		pass_message_args (NULL, MSG_CLIENT_KILL,
			":%s %s account is already registered",
			Server_Name, row[0]);
		pass_message_args (NULL, MSG_SERVER_REGINFO,
			":%s %s %s %s %s %s %s", Server_Name,
			row[0], row[1], row[2], row[3], row[4], row[5]);
	    }
	    mysql_free_result (result);
	    return;
	}

	/* verify the password */
	if (strcmp (field[1], row[1]) != 0)
	{
	    log ("login(): bad password for user %s", row[0]);
	    if (con->class == CLASS_UNKNOWN)
	    {
		send_cmd (con, MSG_SERVER_ERROR, "invalid password");
		con->destroy = 1;
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
		log ("login(): syncing registration info");
		pass_message_args (NULL, MSG_CLIENT_KILL,
			":%s %s invalid password", Server_Name, row[0]);
		pass_message_args (NULL, MSG_SERVER_REGINFO,
			":%s %s %s %s %s %s %s", Server_Name,
			row[0], row[1], row[2], row[3], row[4], row[5]);
	    }

	    mysql_free_result (result);
	    return;
	}

	/* update the last seen time */
	snprintf (Buf, sizeof (Buf),
		"UPDATE accounts SET lastseen=%d WHERE nick='%s'",
		(int)time (0), field[0]);
	if (mysql_query (Db, Buf) != 0)
	    sql_error ("login", Buf);

	/* set the default userlevel */
	if (!strcasecmp ("elite", row[2]))
	    level = LEVEL_ELITE;
	else if (!strcasecmp ("admin", row[2]))
	    level = LEVEL_ADMIN;
	else if (strcasecmp ("moderator", row[2]) == 0)
	    level = LEVEL_MODERATOR;
	else if (strcasecmp ("user", row[2]) != 0)
	{
	    log ("login(): unknown level %s for %s in accounts table",
		    row[2], row[0]);
	}

	if (level > LEVEL_USER)
	{
	    /* broadcast the updated userlevel to our peer servers */
	    if (Num_Servers)
		pass_message_args (con, MSG_CLIENT_SETUSERLEVEL,
			":%s %s %s", Server_Name, row[0] , row[2]);
	    /* notify users of their change in level */
	    send_cmd (con, MSG_SERVER_NOSUCH, "%s set your level to %s (%d).",
		    Server_Name, Levels[level], level);

	    log ("login(): set %s to level %s", row[0], Levels[level]);
	}
    }
    else if (tag == MSG_CLIENT_LOGIN_REGISTER)
    {
	/* create the db entry now */
	log ("login(): registering user %s", field[0]);

	if (numfields < 5)
	{
	    log ("login(): too few fields to register nick");
	    if (con->class == CLASS_UNKNOWN)
	    {
		con->destroy = 1;
		send_cmd (con, MSG_SERVER_ERROR,
			"too few fields in registration message");
		return;
	    }
	}
	snprintf (Buf, sizeof (Buf),
		"INSERT INTO accounts VALUES ('%s','%s','user','%s',%d,%d)",
		field[0], field[1], field[5], (int)time (0), (int)time (0));
	if (mysql_query (Db, Buf) != 0)
	{
	    sql_error ("login", Buf);
	    mysql_free_result (result);
	    if (con->class == CLASS_UNKNOWN)
		send_cmd (con, MSG_SERVER_ERROR, "error creating account");
	    return;
	}
    }

    user = new_user ();
    user->nick = STRDUP (field[0]);
    user->port = atoi (field[2]);
    user->clientinfo = STRDUP (field[3]);
    user->pass = STRDUP (field[1]);
    user->speed = speed;
    user->connected = time (0);
    user->level = level;
    if (tag == MSG_CLIENT_LOGIN_REGISTER)
	user->email = STRDUP (field[5]);
    else if (row)
	user->email = STRDUP (row[3]);
    else
    {
	snprintf (Buf, sizeof (Buf), "anon@%s", Server_Name);
	user->email = STRDUP (Buf);
    }

    hash_add (Users, user->nick, user);

    mysql_free_result (result);

    /* if this is a locally connected user, update our information */
    if (con->class == CLASS_UNKNOWN)
    {
	/* save the ip address of this client */
	user->host = con->ip;
	user->conport = con->port;
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
	send_cmd (con, MSG_SERVER_EMAIL, user->email);
	show_motd (con, 0, 0, NULL);
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

/* check to see if a nick is already registered */
/* 7 <nick> */
HANDLER (register_nick)
{
    int n;
    MYSQL_RES *result;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    log ("register_nick(): attempting to register %s", pkt);
    snprintf (Buf, sizeof (Buf), "SELECT nick FROM accounts WHERE nick='%s'",
	    pkt);
    if (mysql_query (Db, Buf) != 0)
    {
	send_cmd (con, MSG_SERVER_ERROR, "db error");
	sql_error ("register_nick", Buf);
	return;
    }
    result = mysql_store_result (Db);
    if (result == 0)
    {
	log ("register_nick(): NULL result from mysql_store_result()");
	return;
    }
    n = mysql_num_rows (result);
    if (n > 0)
    {
	ASSERT (n == 1);
	send_cmd (con, MSG_SERVER_REGISTER_FAIL, "");
	log ("register_nick(): %s is already registered", pkt);
    }
    else
    {
	send_cmd (con, MSG_SERVER_REGISTER_OK, "");
	log ("register_nick(): %s is not yet registered", pkt);
    }
    mysql_free_result (result);
}

/* 10114 :<server> <nick> <password> <level> <email> <created> <lastseen> */
HANDLER (reginfo)
{
    char *server;
    char *fields[6];
    int n;
    MYSQL_RES *result;
    MYSQL_ROW row;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    if (*pkt != ':')
    {
	log ("reginfo(): message does not begin with :");
	return;
    }
    server = pkt + 1;
    pkt = strchr (server, ' ');
    if (!pkt)
	return;
    *pkt++ = 0;
    if (split_line (fields, sizeof (fields)/sizeof(char*), pkt) != 6)
    {
	log ("reginfo(): wrong number of fields");
	return;
    }
    /* look up any entry we have for this user */
    snprintf (Buf, sizeof (Buf), "SELECT * FROM accounts WHERE nick='%s'",
	    fields[0]);
    if (mysql_query (Db, Buf) != 0)
    {
	sql_error ("reginfo", Buf);
	return;
    }
    result = mysql_store_result (Db);
    n = mysql_num_rows (result);
    if (n > 0)
    {
	ASSERT (n == 1);
	row = mysql_fetch_row (result);
	/* check the timestamp to see if this is more recent than what
	   we have */
	if (atol (fields[4]) > atol (row[4]))
	{
	    /* our record was created first, notify peers */
	    log ("reginfo(): stale reginfo received from %s", server);
	    pass_message_args (NULL, MSG_SERVER_REGINFO,
		    ":%s %s %s %s %s %s %s", Server_Name,
		    row[0], row[1], row[2], row[3], row[4], row[5]);
	    mysql_free_result (result);
	    return;
	}
	mysql_free_result (result);
	/* update our record */
	snprintf (Buf, sizeof (Buf),
	    "UPDATE accounts SET password='%s',level='%s',email='%s',created=%s,lastseen=%s WHERE nick='%s'",
	    fields[1], fields[2], fields[3], fields[4], fields[5], fields[0]);
	if (mysql_query (Db, Buf) != 0)
	    sql_error ("reginfo", Buf);
	log ("reginfo(): updated accounts table for %s", fields[0]);
    }
    else
    {
	mysql_free_result (result);
	/* create the record */
	snprintf (Buf, sizeof (Buf),
	    "INSERT INTO accounts VALUES ('%s','%s','%s','%s',%s,%s)",
	    fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]);
	if (mysql_query (Db, Buf) != 0)
	    sql_error ("reginfo", Buf);
    }
}
