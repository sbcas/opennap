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
    cli->class = CLASS_UNKNOWN;	/* not authenticated yet */
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
    cli->port = port;
    cli->connecting = 1;
    cli->timer = Current_Time;
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
complete_connect (CONNECTION * con)
{
    /* a previous call to read() may have reset the error code */
    if (con->destroy || check_connect_status (con->fd) != 0)
    {
	notify_mods(SERVERLOG_MODE,"Server link to %s failed",con->host);
	con->destroy = 1;
	return;
    }
    con->connecting = 0;	/* connected now */

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
    int argc, port;
    LIST *list;
    CONNECTION *server;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &user) != 0)
	return;
    ASSERT (validate_user (user));

    if (user->level < LEVEL_ADMIN)
    {
	if (ISUSER (con))
	    permission_denied (con);
	return;			/* no privilege */
    }

    argc = split_line (fields, sizeof (fields) / sizeof (char *), pkt);

    if (argc < 2)
    {
	log ("server_connect(): too few fields");
	return;
    }
    port = atoi (fields[1]);
    if (port < 0 || port > 65535)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "Invalid port number");
	return;
    }

    /* check to make sure this server is not already linked */
    if (is_linked (con, fields[0]))
	return;

    if (argc == 2 || (argc == 3 && !strcasecmp (fields[2], Server_Name)))
    {
	/* make sure we aren't already connected to this server */
	for (list = Servers; list; list = list->next)
	{
	    server = list->data;
	    ASSERT (validate_connection (con));
	    ASSERT (ISSERVER (con));
	    if (!strcasecmp (fields[0], server->host) && server->port == port)
	    {
		log ("server_connect(): already linked to %s:%d",
		     fields[0], port);
		send_user (user, MSG_SERVER_NOSUCH,
			   "[%s] %s:%d is already linked", Server_Name,
			   fields[0], port);
		return;
	    }
	}
	try_connect (fields[0], port);
    }
    else
    {
	/* pass the message on the target server */
	ASSERT (argc == 3);
	pass_message_args (con, MSG_CLIENT_CONNECT, ":%s %s %s %s",
			   user->nick, fields[0], fields[1], fields[2]);
    }

    notify_mods (SERVERLOG_MODE, "%s requested server link from %s to %s:%s",
		 user->nick, argc == 3 ? fields[2] : Server_Name, fields[0],
		 fields[1]);
}

/* 10101 [ :<nick> ] <server> <reason> */
HANDLER (server_disconnect)
{
    USER *user;
    char *host;
    CONNECTION *serv;
    LIST *tmpList, **list;

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
    host = next_arg (&pkt);
    for (list = &Servers; *list; list = &(*list)->next)
    {
	serv = (*list)->data;
	ASSERT (validate_connection (serv));
	ASSERT (ISSERVER (serv));
	if (!strcasecmp (serv->host, host))
	{
	    tmpList = *list;
	    *list = (*list)->next;
	    FREE (tmpList);
	    serv->destroy = 1;
	    break;
	}
    }

    pass_message_args (con, MSG_CLIENT_DISCONNECT, ":%s %s %s",
		       user->nick, host, NONULL (pkt));
    notify_mods (SERVERLOG_MODE, "%s disconnected server %s: %s", user->nick,
		 host, NONULL (pkt));
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
    ASSERT (pkt != 0);
    if (pop_user (con, &pkt, &user) != 0)
	return;
    ASSERT (validate_user (user));
    if (user->level < LEVEL_ELITE)
    {
	permission_denied (con);
	return;
    }
    server = next_arg (&pkt);
    if (!server)
    {
	unparsable (con);
	return;
    }
    pass_message_args (con, MSG_CLIENT_KILL_SERVER, ":%s %s %s",
		       user->nick, server, NONULL (pkt));
    notify_mods (SERVERLOG_MODE, "%s killed server %s: %s", user->nick,
		 server, NONULL (pkt));

    if (!strcasecmp (server, Server_Name))
    {
	log ("kill_server(): shutdown by %s: %s", user->nick, NONULL (pkt));
	SigCaught = 1;		/* this causes the main event loop to exit */
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
    else
	pass_message_args (con, tag, ":%s %s", user->nick, pkt);
}

/* 404 <message> */
HANDLER (server_error)
{
    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_SERVER_CLASS ("server_error");
    notify_mods (ERROR_MODE, "server %s sent error message: %s", con->host,
		 pkt);
}

static void
link_collision (CONNECTION * con, char *server, int port, char *peer,
		int peerport)
{
    int tag;

    log ("link_collision(): already linked (%s:%d -> %s:%d)",
	 server, port, peer, peerport);

    if (ISUSER (con))
	tag = MSG_SERVER_NOSUCH;
    else
    {
	tag = MSG_SERVER_ERROR;
	log ("link_collision(): terminating server connection to avoid loop");
	con->destroy = 1;
    }
    send_cmd (con, tag, "already linked (%s:%d -> %s:%d)",
	      server, port, peer, peerport);
}

int
is_linked (CONNECTION * con, const char *host)
{
    LIST *list;
    LINK *link;
    CONNECTION *serv;

    /* check local links */
    for (list = Servers; list; list = list->next)
    {
	serv = list->data;
	if (!strcasecmp (serv->host, host))
	{
	    link_collision (con, Server_Name, get_local_port (serv->fd),
			    serv->host, serv->port);
	    return 1;
	}
    }

    /* check remote links */
    for (list = Server_Links; list; list = list->next)
    {
	link = list->data;
	if (!strcasecmp (link->server, host)
	    || !strcasecmp (link->peer, host))
	{
	    link_collision (con, link->server, link->port, link->peer,
			    link->peerport);
	    return 1;
	}
    }
    return 0;
}
