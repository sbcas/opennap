/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.

   $Id$ */

#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
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
    char *pass = 0;

    db = textdb_init (Server_Db_Path);
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

    /* make sure this connection is coming from where they say they are */
    /* TODO: make this nonblocking for the rest of the server */
    ip = lookup_ip (fields[0]);

    if (ip != con->ip)
    {
	send_cmd (con, MSG_SERVER_ERROR,
		  "your ip address does not match that name");
	log ("server_login(): %s does not resolve to %s", fields[0],
	     my_ntoa (con->ip));
	con->destroy = 1;
	return;
    }

    /* see if there is any entry for this server */
    if ((pass = get_server_pass (con->host)) == 0)
    {
	log ("server_login(): no entry for server %s", con->host);
	send_cmd (con, MSG_SERVER_ERROR, "Permission Denied");
	con->destroy = 1;
	return;
    }
    FREE (pass);

    FREE (con->host);
    con->host = STRDUP (fields[0]);

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
    con->compress =  (compress < Compression_Level) ? compress : Compression_Level;

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

	log ("server_login(): peer initiated connection, sending login request");
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
    if(!con->opt.auth->sendernonce)
    {
	OUTOFMEMORY("server_login");
	con->destroy=1;
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

    log ("server_login(): server %s has joined", con->host);

    notify_mods ("server %s has joined.", con->host);

    con->class = CLASS_SERVER;
    con->opt.server = CALLOC (1, sizeof (SERVER));
#if HAVE_LIBZ
    /* set up the compression handlers for this connection */
    init_compress (con, con->compress);
#endif

    /* put this connection in the shortcut list to the server conections */
    add_server (con);

    /* synchronize our state with this server */
    synch_server (con);
}
