/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.

   $Id$ */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include "opennap.h"
#include "debug.h"

static void
try_connect (char *host, int port)
{
    int f;
    CONNECTION *cli;
    unsigned int ip;

    /* attempt a connection.  we do this nonblocking so that the server
       doesn't halt if it takes a long time to connect */
    f = make_tcp_connection (host, port, &ip);
    if (f == -1)
	return;

    cli = new_connection ();
    if (!cli)
	goto error;
    cli->class = CLASS_UNKNOWN; /* not authenticated yet */
    cli->fd = f;
    cli->host = STRDUP (host);
    if (!cli->host)
    {
	OUTOFMEMORY ("try_connect");
	goto error;
    }
    cli->server_login = 1;
    if ((cli->opt.auth = CALLOC (1, sizeof (AUTH))) == 0)
    {
	OUTOFMEMORY ("try_connect");
	goto error;
    }
    cli->opt.auth->nonce = generate_nonce ();
    if (!cli->opt.auth->nonce)
    {
	log ("try_connect(): could not generate nonce, closing connection");
	goto error;
    }
    cli->ip = ip;
    cli->connecting = 1;
    add_client (cli);
    return;
error:
    log ("try_connect(): closing connection");
    CLOSE (f);
    if (cli)
    {
	if (cli->host)
	    FREE (cli->host);
	if (cli->opt.auth)
	{
	    if (cli->opt.auth->nonce)
		FREE (cli->opt.auth->nonce);
	    FREE (cli->opt.auth);
	}
	FREE (cli);
    }
}

void
complete_connect (CONNECTION *con)
{
    if (check_connect_status (con->fd) != 0)
    {
	con->destroy = 1;
	return;
    }
    con->connecting = 0; /* connected now */

    /* send the login request */
    ASSERT (Server_Name != 0);
    ASSERT (con->server_login == 1);
    ASSERT (con->opt.auth != 0);
    send_cmd (con, MSG_SERVER_LOGIN, "%s %s %d", Server_Name,
	    con->opt.auth->nonce, Compression_Level);

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
    int i, argc;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("server_connect");
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
	/* make sure we aren't already connected to this server */
	for (i = 0; i < Num_Servers; i++)
	{
	    if (!strcasecmp (fields[0], Servers[i]->host))
	    {
		log ("server_connect(): %s tried to link server %s, but it is already connected",
			user->nick, fields[0]);
		if (con->class == CLASS_USER)
		    send_cmd (con, MSG_SERVER_NOSUCH,
			    "server %s is already connected", fields[0]);
		return;
	    }
	}
	try_connect (fields[0], atoi (fields[1]));
    }
    else if (Num_Servers)
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
    if (Num_Servers)
	pass_message_args (con, MSG_CLIENT_DISCONNECT, ":%s %s %s",
		user->nick, pkt, reason ? reason : "disconnect");
    notify_mods ("%s disconnected server %s: %s", user->nick, pkt,
	    NONULL(reason));
    /* if its a locally connected server, shut it down now */
    if(i<Num_Servers)
    {
	serv = Servers[i];
	Servers = array_remove (Servers, &Num_Servers, Servers[i]);
	serv->destroy = 1;
    }
}

/* 10110 [ :<user> ] <server> [ <reason> ] */
/* force the server process to die */
HANDLER (kill_server)
{
    USER *user;
    char *server;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &user) != 0)
	return;
    ASSERT (validate_user (user));
    if (user->level < LEVEL_ELITE)
    {
	log("kill_server(): %s attempted to kill the server", user->nick);
	if (con->class == CLASS_USER)
	    permission_denied (con);
	return;
    }
    server=next_arg(&pkt);

    if(Num_Servers)
	pass_message_args (con, MSG_CLIENT_KILL_SERVER, ":%s %s %s",
		user->nick, server, NONULL(pkt));
    notify_mods ("%s killed server %s: %s", user->nick, server,
	    NONULL(pkt));

    if (!strcasecmp (server, Server_Name))
    {
	log("kill_server(): shutdown by %s: %s", user->nick, NONULL(pkt));
	SigCaught = 1; /* this causes the main event loop to exit */
    }
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
#if 0
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
#endif
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
	send_user (user, MSG_SERVER_NOSUCH, "--");
	send_user (user, MSG_SERVER_NOSUCH, "%s %s", PACKAGE, VERSION);
	send_user (user, MSG_SERVER_NOSUCH, "--");
    }
    else if (Num_Servers)
	pass_message_args(con,tag,":%s %s", user->nick, pkt);
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
