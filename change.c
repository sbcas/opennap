/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#ifdef WIN32
#include <windows.h>
#endif /* WIN32 */
#include <stdlib.h>
#include <mysql.h>
#include "opennap.h"
#include "debug.h"

extern MYSQL *Db;

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
	if (con->class == CLASS_USER && Num_Servers)
	{
	    pass_message_args (con, MSG_CLIENT_CHANGE_DATA_PORT, ":%s %d",
		    user->nick, user->port);
	}
    }
    else if (con->class == CLASS_USER)
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
	/* if a local user, pass this info to our peer servers */
	if (con->class == CLASS_USER && Num_Servers)
	{
	    pass_message_args (con, MSG_CLIENT_CHANGE_SPEED, ":%s %d",
		    user->nick, spd);
	}
	snprintf (Buf, sizeof (Buf),
		"UPDATE library SET linespeed=%d WHERE owner='%s'",
		spd, user->nick);
	if (mysql_query (Db, Buf) != 0)
	{
	    sql_error ("change_speed", Buf);
	    return;
	}
    }
    else if (con->class == CLASS_USER)
	send_cmd (con, MSG_SERVER_NOSUCH, "invalid speed");
}

/* 701 [ :<user> ] <password>
   change user password */
HANDLER (change_pass)
{
    USER *user;

    (void) tag;
    (void) len;
    if (pop_user (con, &pkt, &user) != 0)
	return;
    snprintf (Buf, sizeof (Buf),
	"UPDATE accounts SET password='%s' WHERE nick='%s'", pkt, user->nick);
    if (mysql_query (Db, Buf) != 0)
    {
	sql_error ("change_pass", Buf);
	if (con->class == CLASS_USER)
	    send_cmd (con, MSG_SERVER_NOSUCH, "db error");
    }
}

/* 702 [ :<user> ] <email>
   change email address */
HANDLER (change_email)
{
    USER *user;

    (void) tag;
    (void) len;
    if (pop_user (con, &pkt, &user) != 0)
	return;
    snprintf (Buf, sizeof (Buf),
	"UPDATE accounts SET email='%s' WHERE nick='%s'", pkt, user->nick);
    if (mysql_query (Db, Buf) != 0)
    {
	sql_error ("change_email", Buf);
	if (con->class == CLASS_USER)
	    send_cmd (con, MSG_SERVER_NOSUCH, "db error");
    }
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
    if (user->con)
	send_cmd (user->con, MSG_CLIENT_ALTER_PORT, "%d", p);

    /* if a local admin issued the command, pass it to our peer servers.
       note that we do this even if the target was local, because all servers
       need to know what the new port is */
    if (con->class == CLASS_USER && Num_Servers)
	pass_message_args (con, MSG_CLIENT_ALTER_PORT, ":%s %s %d",
		sender->nick, user->nick, p);

    notify_mods ("%s changed %d's data port to %d: %s", sender->nick,
	    user->nick, p, pkt ? pkt : "");
}
