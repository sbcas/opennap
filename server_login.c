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

/* this happens infrequent enough that we just open it each time we need to
   instead of leaving it open */
static char *
get_server_pass (const char *host, char **localPass /* optional */ )
{
    char path[_POSIX_PATH_MAX], *av[3], *pass = 0;
    int ac;
    FILE *fp;

    if (localPass)
	*localPass = 0;

    snprintf (path, sizeof (path), "%s/servers", Config_Dir);
    fp = fopen (path, "r");
    if (!fp)
    {
	logerr ("get_server_pass", path);
	return 0;
    }
    Buf[sizeof (Buf) - 1] = 0;
    while (fgets (Buf, sizeof (Buf) - 1, fp))
    {
	/* skip comments and blanck lines */
	if (Buf[0] == '#' || Buf[0] == '\n'
	    || (Buf[0] == '\r' || Buf[1] == '\n'))
	    continue;
	/* each line is composed of: <server> <password> [ <mypass> ] */
	ac = split_line (av, FIELDS (av), Buf);
	if (ac > 1)
	{
	    if (!strcasecmp (host, av[0]))
	    {
		/* return the remote server's expected password */
		pass = STRDUP (av[1]);
		if (!pass)
		{
		    OUTOFMEMORY ("get_server_pass");
		    break;
		}
		if (localPass)
		{
		    *localPass = STRDUP ((ac > 2) ? av[2] : Server_Pass);
		    if (!*localPass)
		    {
			OUTOFMEMORY ("get_server_pass");
			/* force the operation to fail so there is no
			   possibility of sniffing the default password */
			FREE (pass);
			pass = 0;
		    }
		}
		break;
	    }
	}
	else
	{
	    log ("get_server_pass(): too few parameters for server %s",
		 (ac > 0) ? av[0] : "<unknown>");
	}
    }
    fclose (fp);
    return pass;
}

/* process a request to establish a peer server connection */
/* <name> <nonce> <compression> */
HANDLER (server_login)
{
    char *fields[3];
    char hash[33];
    char *pass, *localPass = 0;
    unsigned int ip;
    struct md5_ctx md;
    int compress;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (con->class != CLASS_UNKNOWN)
    {
	send_cmd (con, MSG_SERVER_ERROR, "reregistration is not supported");
	con->destroy = 1;
	return;
    }

    if (split_line (fields, sizeof (fields) / sizeof (char *), pkt) != 3)
    {
	log ("server_login(): wrong number of fields");
	send_cmd (con, MSG_SERVER_ERROR, "wrong number of fields");
	con->destroy = 1;
	return;
    }

    log("server_login(): request from %s (%s)", fields[0], con->host);

    /* check to see if this server is already linked */
    if (is_linked (con, fields[0]))
	return;

    /* make sure this connection is coming from where they say they are */
    /* TODO: make this nonblocking for the rest of the server */
    ip = lookup_ip (fields[0]);

    if (ip != con->ip)
    {
	log("server_login(): %s does not match %s (%s)",
		con->host, fields[0], my_ntoa(ip));
	send_cmd (con, MSG_SERVER_ERROR,
		  "Your IP address does not match that name");
	notify_mods(SERVERLOG_MODE,"Failed server connect from %s != %s",
		con->host, fields[0]);
	con->destroy = 1;
	return;
    }

    FREE (con->host);
    con->host = STRDUP (fields[0]);

    /* notify local admins of the connection request */
    notify_mods (SERVERLOG_MODE, "Server login request from %s", con->host);

    /* see if there is any entry for this server */
    if ((pass = get_server_pass (con->host, &localPass)) == 0)
    {
	log("server_login(): no servers entry for %s", con->host);
	notify_mods(SERVERLOG_MODE,
		"Failed server login from %s (%s): no entry in servers file",
		fields[0], con->host);
	send_cmd (con, MSG_SERVER_ERROR, "Permission Denied");
	con->destroy = 1;
	if (localPass)
	    FREE (localPass);
	return;
    }
    FREE (pass);

    compress = atoi (fields[2]);
    if (compress < 0 || compress > 9)
    {
	log("server_login(): invalid compression level %s", fields[2]);
	notify_mods(SERVERLOG_MODE,
		"Failed server login from %s: invalid compression level %s",
		con->host, fields[2]);
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

	if ((con->opt.auth->nonce = generate_nonce ()) == NULL)
	{
	    log("server_login(): failed to generate nonce");
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
    ASSERT (localPass != 0);
    md5_process_bytes (localPass, strlen (localPass), &md);
    md5_finish_ctx (&md, hash);
    expand_hex (hash, 16);
    hash[32] = 0;

    /* send the response */
    send_cmd (con, MSG_SERVER_LOGIN_ACK, hash);

    FREE (localPass);

    log("server_login(): ACK for %s sent", con->host);
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
	return;
    }
    if (!con->server_login)
    {
	send_cmd (con, MSG_SERVER_ERROR, "You must login first");
	con->destroy = 1;
	return;
    }

    /* look up the entry in our peer servers database */
    pass = get_server_pass (con->host, NULL);
    if (!pass)
    {
	log("server_login_ack(): unable to find password for %s", con->host);
	notify_mods(SERVERLOG_MODE,
		"Failed server login from %s: no password found", con->host);
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
	log("server_login(): invalid password for %s", con->host);
	notify_mods(SERVERLOG_MODE,
		"Failed server login from %s: invalid password", con->host);
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
    /* set up the compression handlers for this connection */
    init_compress (con, con->compress);

    log("server_login_ack(): server %s has joined", con->host);

    notify_mods (SERVERLOG_MODE, "Server %s has joined", con->host);

    /* notify peer servers this server has joined the cluster */
    pass_message_args (con, MSG_SERVER_LINK_INFO, "%s %hu %s %hu 1",
		       Server_Name, get_local_port (con->fd), con->host,
		       con->port);

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
	send_cmd (con, MSG_SERVER_NOSUCH,
		  "Wrong number of parameters for command %d", tag);
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
	send_cmd (con, MSG_SERVER_NOSUCH, "Invalid hop count %d",
		  slink->hops);
	slink->hops = 1;	/* at least */
    }
    log ("link_info(): %s:%d -> %s:%d (%d hops away)",
	 slink->peer, slink->peerport, slink->server, slink->port,
	 slink->hops);
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
    /* remove all link info for any servers behind the one that just
       disconnected */
    for (list = Server_Links; list; list = list->next)
    {
	link = list->data;
	if (!strcasecmp (link->server, av[0]) &&
	    !strcasecmp (link->peer, av[1]))
	{
	    link->port = -1;
	    link->peerport = -1;
	    remove_links (link->peer);
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
	if (link->port != (unsigned short) -1 &&
	    link->peerport != (unsigned short) -1 &&
	    !strcasecmp (host, link->server))
	{
	    link->port = -1;
	    link->peerport = -1;
	    mark_links (link->peer);	/* mark servers connected to this peer */
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
	if (link->port == (unsigned short) -1 &&
	    link->peerport == (unsigned short) -1)
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
