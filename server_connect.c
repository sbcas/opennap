/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.

   $Id$ */

#include <stdlib.h>
#include <string.h>
#include <mysql.h>
#include "opennap.h"
#include "debug.h"

extern MYSQL *Db;

static void
try_connect (char *host, int port)
{
    int f;
    CONNECTION *cli;
    unsigned long ip;

    /* attempt a connection.  we do this nonblocking so that the server
       doesn't halt if it takes a long time to connect */
    f = make_tcp_connection (host, port, &ip);
    if (f == -1)
	return;

    cli = new_connection ();
    cli->class = CLASS_UNKNOWN; /* not authenticated yet */
    cli->fd = f;
    cli->host = STRDUP (host);
    cli->nonce = generate_nonce ();
    cli->ip = ip;
    cli->flags |= FLAG_CONNECTING;

    add_client (cli);
}

void
complete_connect (CONNECTION *con)
{
    if (check_connect_status (con->fd) != 0)
    {
	remove_connection (con);
	return;
    }

    con->flags &= ~FLAG_CONNECTING; /* connected now */

    /* send the login request */
    ASSERT (Server_Name != 0);
    send_cmd (con, MSG_SERVER_LOGIN, "%s %s %d", Server_Name, con->nonce,
	Compression_Level);

    /* we handle the response to the login request in the main event loop so
       that we don't block while waiting for th reply.  if the server does
       not accept our connection it will just drop it and we will detect
       it by the normal means that every other connection is checked */

    log ("complete_connect(): connection to %s established.", con->host);
}

/* process client request to link another server */
/* 10100 [ :<user> ] <server-name> <port> [ <remote_server> ] */
HANDLER (server_connect)
{
    USER *user;
    char *fields[3];
    int argc;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &user) != 0)
	return;
    ASSERT (validate_user (user));

    if (user->level < LEVEL_ADMIN)
    {
	if (con->class == CLASS_USER)
	    permission_denied (con);
	return; /* no privilege */
    }

    argc = split_line (fields, sizeof (fields) / sizeof (char *), pkt);
    if (argc < 2)
    {
	log ("server_connect(): too few fields");
	return;
    }

    if (argc == 2 || (argc == 3 && !strcasecmp (fields[2], Server_Name)))
    {
	try_connect (fields[0], atoi (fields[1]));
    }
    else if (con->class == CLASS_USER)
    {
	/* pass the message on the target server */
	ASSERT (argc == 3);
	pass_message_args (con, MSG_CLIENT_CONNECT, ":%s %s %s %s",
	    user->nick, fields[0], fields[1], fields[2]);
    }

    notify_mods ("%s requested server link from %s to %s:%s",
	user->nick, argc == 3 ? fields[2] : Server_Name, fields[0], fields[1]);
}

/* 10101 [ :<nick> ] <server> <reason> */
HANDLER (server_disconnect)
{
    USER *user;
    char *reason;
    int i;
    CONNECTION *serv;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &user) != 0)
	return;
    ASSERT (validate_user (user));
    if (user->level < LEVEL_ADMIN)
    {
	if (con->class == CLASS_USER)
	    permission_denied (con);
	return;
    }
    reason = strchr (pkt, ' ');
    if (reason)
	*reason++ = 0;
    for (i = 0; i < Num_Servers; i++)
	if (!strcasecmp (Servers[i]->host, pkt))
	    break;
    if (i == Num_Servers)
    {
	if (con->class == CLASS_USER)
	    pass_message_args (con, MSG_CLIENT_DISCONNECT, ":%s %s %s",
		user->nick, pkt, reason ? reason : "disconnect");
	return;
    }
    notify_mods ("%s disconnected server %s: %s", user->nick, pkt,
	reason ? reason : "");
    serv = Servers[i];
    Servers = array_remove (Servers, &Num_Servers, Servers[i]);
    remove_connection (serv);
}

/* 10110 [ :<user> ] <server> <reason> */
HANDLER (kill_server)
{
    USER *user;
    char *reason;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &user) != 0)
	return;
    ASSERT (validate_user (user));
    if (user->level < LEVEL_ELITE)
    {
	if (con->class == CLASS_USER)
	    permission_denied (con);
	return;
    }
    reason = strchr (pkt, ' ');
    if (reason)
	*reason++ = 0;

    if (con->class == CLASS_USER)
    	pass_message_args (con, MSG_CLIENT_KILL_SERVER, ":%s %s %s",
	    user->nick, pkt, reason ? reason : "");
    notify_mods ("%s killed server %s: %s", user->nick, pkt,
	reason ? reason : "");

    if (!strcasecmp (pkt, Server_Name))
	SigCaught = 1; /* this causes the main event loop to exit */
}

/* 10111 <server> [ <reason> ] */
HANDLER (remove_server)
{
    char *reason;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    /* TODO: should we be able to remove any server, or just from the local
       server? */
    CHECK_USER_CLASS ("remove_server");
    ASSERT (validate_user (con->user));
    if (con->user->level < LEVEL_ELITE)
    {
	permission_denied (con);
	return;
    }
    reason = strchr (pkt, ' ');
    if (reason)
	*reason++ = 0;
    snprintf (Buf, sizeof (Buf), "DELETE FROM servers WHERE server = '%s'",
	pkt);
    if (mysql_query (Db, Buf) != 0)
    {
	sql_error ("remove_server", Buf);
	send_cmd (con, MSG_SERVER_NOSUCH,
	    "error removing %s from SQL database", pkt);
    }
    else
    {
	notify_mods ("%s removed server %s from database: %s",
	    con->user->nick, pkt, reason ? reason : "");
    }
}

/* 801 [ :<user> ] [ <server> ] */
HANDLER (server_version)
{
    USER *user;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &user) != 0)
	return;
    ASSERT (validate_user (user));
    if (user->level < LEVEL_MODERATOR)
    {
	if (con->class == CLASS_USER)
	    permission_denied (con);
	return;
    }
    if (!*pkt || !strcmp (Server_Name, pkt))
    {
	if (user->con)
	{
	    send_cmd (user->con, MSG_SERVER_NOSUCH, "--");
	    send_cmd (user->con, MSG_SERVER_NOSUCH, "%s %s", PACKAGE, VERSION);
	    send_cmd (user->con, MSG_SERVER_NOSUCH, "--");
	}
	else
	{
	    ASSERT (0);
	    log ("server_version(): haven't implemented sending error messages to remote users");
	}
    }
}

/* 404 <message> */
HANDLER (server_error)
{
    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_SERVER_CLASS ("server_error");
    notify_mods ("server %s sent error message: %s", con->host, pkt);
}
