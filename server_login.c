/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.

   $Id$ */

#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include "opennap.h"
#include "debug.h"
#include "md5.h"
#include "textdb.h"

/* this happens infrequent enough that we just open it each time we need to
   instead of leaving it open */
static char *
get_server_pass (const char *host)
{
    TEXTDB *db;
    TEXTDB_RES *result;
    char *pass = 0, path[_POSIX_PATH_MAX];

    snprintf(path,sizeof(path),"%s/servers",Config_Dir);
    db = textdb_init (path);
    if (db)
    {
	result = textdb_fetch (db, host);
	if (result)
	{
	    if (list_count (result->columns) < 2)
	    {
		log ("get_server_pass(): bogus entry for server %s",
		     (char *) result->columns->data);
	    }
	    else
		pass = STRDUP (result->columns->next->data);
	    textdb_free_result (result);
	}
	textdb_close (db);
    }
    else
    {
	log ("get_server_pass(): textdb_init failed");
    }
    return pass;
}

/* process a request to establish a peer server connection */
/* <name> <nonce> <compression> */
HANDLER (server_login)
{
    char *fields[3];
    char hash[33];
    char *pass;
    unsigned int ip;
    struct md5_ctx md;
    int compress;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (con->class != CLASS_UNKNOWN)
    {
	log ("server_login(): %s tried to login, but is already registered",
	     con->host);
	send_cmd (con, MSG_SERVER_ERROR, "reregistration is not supported");
	con->destroy = 1;
	return;
    }

    /* TODO: ensure that this server is not already connected */

    if (split_line (fields, sizeof (fields) / sizeof (char *), pkt) != 3)
    {
	log ("server_login(): wrong number of fields");
	send_cmd (con, MSG_SERVER_ERROR, "wrong number of fields");
	con->destroy = 1;
	return;
    }

    /* check to see if this server is already linked */
    if (is_linked (con, fields[0]))
	return;

    /* make sure this connection is coming from where they say they are */
    /* TODO: make this nonblocking for the rest of the server */
    ip = lookup_ip (fields[0]);

    if (ip != con->ip)
    {
	send_cmd (con, MSG_SERVER_ERROR,
		  "Your IP address does not match that name");
	log ("server_login(): %s does not resolve to %s", fields[0],
	     my_ntoa (con->ip));
	con->destroy = 1;
	return;
    }

    FREE (con->host);
    con->host = STRDUP (fields[0]);

    /* notify local admins of the connection request */
    notify_mods (SERVERLOG_MODE, "Received server login request from %s", con->host);

    /* see if there is any entry for this server */
    if ((pass = get_server_pass (con->host)) == 0)
    {
	log ("server_login(): no entry for server %s", con->host);
	send_cmd (con, MSG_SERVER_ERROR, "Permission Denied");
	con->destroy = 1;
	return;
    }
    FREE (pass);

    compress = atoi (fields[2]);
    if (compress < 0 || compress > 9)
    {
	log ("server_login: invalid compression level (%d) from %s",
	     compress, con->host);
	send_cmd (con, MSG_SERVER_ERROR, "invalid compression level %d",
		  compress);
	con->destroy = 1;
	return;
    }
    con->compress =
	(compress < Compression_Level) ? compress : Compression_Level;

    /* if this is a new request, set up the authentication info now */
    if (!con->server_login)
    {
	con->server_login = 1;
	if ((con->opt.auth = CALLOC (1, sizeof (AUTH))) == 0)
	{
	    OUTOFMEMORY ("server_login");
	    con->destroy = 1;
	    return;
	}

	log
	    ("server_login(): peer initiated connection, sending login request");
	if ((con->opt.auth->nonce = generate_nonce ()) == NULL)
	{
	    send_cmd (con, MSG_SERVER_ERROR, "unable to generate nonce");
	    con->destroy = 1;
	    return;
	}

	/* respond with our own login request */
	send_cmd (con, MSG_SERVER_LOGIN, "%s %s %d", Server_Name,
		  con->opt.auth->nonce, con->compress);
    }

    con->opt.auth->sendernonce = STRDUP (fields[1]);
    if (!con->opt.auth->sendernonce)
    {
	OUTOFMEMORY ("server_login");
	con->destroy = 1;
	return;
    }

    /* send our challenge response */
    /* hash the peers nonce, our nonce and then our password */
    md5_init_ctx (&md);
    md5_process_bytes (con->opt.auth->sendernonce,
		       strlen (con->opt.auth->sendernonce), &md);
    md5_process_bytes (con->opt.auth->nonce, strlen (con->opt.auth->nonce),
		       &md);
    md5_process_bytes (Server_Pass, strlen (Server_Pass), &md);
    md5_finish_ctx (&md, hash);
    expand_hex (hash, 16);
    hash[32] = 0;

    /* send the response */
    send_cmd (con, MSG_SERVER_LOGIN_ACK, hash);

    /* now we wait for the peers ACK */
    log ("server_login(): sent login ACK");
}

HANDLER (server_login_ack)
{
    struct md5_ctx md5;
    char hash[33];
    char *pass;
    LIST *list;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    if (con->class != CLASS_UNKNOWN)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "reregistration is not supported");
	log ("server_login_ack(): already registered!");
	return;
    }
    if (!con->server_login)
    {
	send_cmd (con, MSG_SERVER_ERROR, "You must login first");
	log ("server_login_ack(): received ACK with no LOGIN?");
	con->destroy = 1;
	return;
    }

    /* look up the entry in our peer servers database */
    pass = get_server_pass (con->host);
    if (!pass)
    {
	log ("server_login_ack(): unable to find server %s", con->host);
	send_cmd (con, MSG_SERVER_ERROR, "Permission Denied");
	con->destroy = 1;
	return;
    }

    /* check the peers challenge response */
    md5_init_ctx (&md5);
    md5_process_bytes (con->opt.auth->nonce, strlen (con->opt.auth->nonce),
		       &md5);
    md5_process_bytes (con->opt.auth->sendernonce,
		       strlen (con->opt.auth->sendernonce), &md5);
    md5_process_bytes (pass, strlen (pass), &md5);	/* password for them */
    md5_finish_ctx (&md5, hash);
    expand_hex (hash, 16);
    hash[32] = 0;

    FREE (pass);

    if (strcmp (hash, pkt) != 0)
    {
	log ("server_login_ack(): incorrect response for server %s",
	     con->host);
	log
	    ("server_login_ack(): remote nonce=%s, my nonce=%s, their hash=%s, expected hash=%s",
	     con->opt.auth->sendernonce, con->opt.auth->nonce, pkt, hash);

	send_cmd (con, MSG_SERVER_ERROR, "Permission Denied");
	con->destroy = 1;
	return;
    }

    /* done with authentication, free resources */
    FREE (con->opt.auth->nonce);
    FREE (con->opt.auth->sendernonce);
    FREE (con->opt.auth);
    con->server_login = 0;

    /* set the recv/send buffer length to 16k for server links */
    set_tcp_buffer_len (con->fd, 16384);

    /* put this connection in the shortcut list to the server conections */
    list = CALLOC (1, sizeof (LIST));
    if (!list)
    {
	OUTOFMEMORY ("server_login_ack");
	con->destroy = 1;
	return;
    }

    list->data = con;
    Servers = list_append (Servers, list);

    con->class = CLASS_SERVER;
    con->opt.server = CALLOC (1, sizeof (SERVER));
#if HAVE_LIBZ
    /* set up the compression handlers for this connection */
    init_compress (con, con->compress);
#endif

    log ("server_login(): server %s has joined", con->host);

    notify_mods (SERVERLOG_MODE, "Server %s has joined", con->host);

    /* notify peer servers this server has joined the cluster */
    pass_message_args (con, MSG_SERVER_LINK_INFO, "%s %hu %s %hu 1",
	Server_Name, get_local_port (con->fd), con->host, con->port);

    /* synchronize our state with this server */
    synch_server (con);
}

/* 10019 <server> <port> <peer> <peerport> <hops> */
HANDLER (link_info)
{
    int ac, port;
    char *av[5];
    LIST *list;
    LINK *slink;

    ASSERT (validate_connection (con));
    CHECK_SERVER_CLASS ("link_info");
    (void) len;
    ac = split_line (av, FIELDS (av), pkt);
    if (ac != 5)
    {
	log ("link_info(): wrong number of parameters");
	print_args (ac, av);
	send_cmd (con, MSG_SERVER_NOSUCH, "Wrong number of parameters for command %d", tag);
	return;
    }
    slink = CALLOC (1, sizeof (LINK));
    if (slink)
    {
	slink->server = STRDUP (av[0]);
	slink->peer = STRDUP (av[2]);
    }
    if (!slink || !slink->server || !slink->peer)
    {
	OUTOFMEMORY ("link_info");
	goto error;
    }
    port = atoi (av[1]);
    if (port < 0 || port > 65535)
    {
	log ("link_info(): invalid port %d", port);
	send_cmd (con, MSG_SERVER_NOSUCH, "Invalid port %d", port);
	port = 0;
    }
    slink->port = port;
    port = atoi (av[3]);
    if (port < 0 || port > 65535)
    {
	log ("link_info(): invalid port %d", port);
	send_cmd (con, MSG_SERVER_NOSUCH, "Invalid port %d", port);
	port = 0;
    }
    slink->peerport = port;
    slink->hops = atoi (av[4]);
    if (slink->hops < 0)
    {
	log ("link_info(): invalid hop count %d", slink->hops);
	send_cmd (con, MSG_SERVER_NOSUCH, "Invalid hop count %d", slink->hops);
	slink->hops = 1;	/* at least */
    }
    log ("link_info(): %s:%d -> %s:%d (%d hops away)",
	slink->peer, slink->peerport, slink->server, slink->port, slink->hops);
    list = CALLOC (1, sizeof (LIST));
    if (!list)
    {
	OUTOFMEMORY ("link_info");
	goto error;
    }
    list->data = slink;
    Server_Links = list_append (Server_Links, list);
    pass_message_args (con, tag, "%s %d %s %d %d", slink->server, slink->port,
	slink->peer, slink->peerport, slink->hops + 1);
    notify_mods (SERVERLOG_MODE, "Server %s has joined", slink->peer);
    return;
error:
    if (slink)
    {
	if (slink->server)
	    FREE (slink->server);
	if (slink->peer)
	    FREE (slink->peer);
	FREE (slink);
    }
}

/* 10020 :<sender> <server>
   <sender> is reporting that <server> has disconnected from the cluster */
HANDLER (server_quit)
{
    int ac;
    char *av[2];
    LIST *list;
    LINK *link;

    ASSERT (validate_connection (con));
    CHECK_SERVER_CLASS ("server_quit");
    (void) len;
    if (*pkt != ':')
    {
	log ("server_quit(): malformed message");
	send_cmd (con, MSG_SERVER_NOSUCH, "Invalid server quit message");
	return;
    }
    ac = split_line (av, FIELDS (av), pkt + 1);
    if (ac != 2)
    {
	log ("server_quit(): wrong number of parameters");
	send_cmd (con, MSG_SERVER_NOSUCH,
		  "Invalid number of parameters for server quit");
	return;
    }
    log ("server_quit(): %s reported that %s has quit", av[0], av[1]);
    /* remove all link info for any servers behind the one that just
       disconnected */
    for(list=Server_Links;list;list=list->next)
    {
	link=list->data;
	if(!strcasecmp(link->server,av[0]) &&
		!strcasecmp(link->peer,av[1]))
	{
	    link->port=-1;
	    link->peerport=-1;
	    remove_links(link->peer);
	    break;
	}
    }

    /* notify interested parties */
    notify_mods (SERVERLOG_MODE, "Server %s has quit", av[1]);
    /* pass along to peers */
    pass_message_args (con, tag, ":%s %s", av[0], av[1]);
}

/* recursively mark entries to reap */
static void
mark_links (const char *host)
{
    LIST *list = Server_Links;
    LINK *link;

    ASSERT (host != 0);
    for (; list; list = list->next)
    {
	link = list->data;
	ASSERT (link != 0);
	if (link->port != (unsigned short)-1 &&
		link->peerport != (unsigned short)-1 &&
		!strcasecmp (host, link->server))
	{
	    link->port = -1;
	    link->peerport = -1;
	    mark_links (link->peer); /* mark servers connected to this peer */
	}
    }
}

/* reap all server link info behind the server named by `host' */
void
remove_links (const char *host)
{
    LIST **list, *tmpList;
    LINK *link;

    mark_links (host);
    list = &Server_Links;
    while (*list)
    {
	link = (*list)->data;
	if (link->port == (unsigned short)-1 &&
	    link->peerport == (unsigned short)-1)
	{
	    tmpList = *list;
	    *list = (*list)->next;
	    FREE (tmpList);
	    FREE (link->server);
	    FREE (link->peer);
	    FREE (link);
	    continue;
	}
	list = &(*list)->next;
    }
}
