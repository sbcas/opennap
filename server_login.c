/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.

   $Id$ */

#include <unistd.h>
#include <mysql.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"
#include "md5.h"

extern MYSQL *Db;

/* process a request to establish a peer server connection */
/* <name> <nonce> <compression> */
HANDLER (server_login)
{
    char *fields[3];
    unsigned int ip;
    struct md5_ctx md;
    char hash[33];

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (con->class != CLASS_UNKNOWN)
    {
	log ("server_login(): %s tried to login, but is already registered",
		con->host);
	send_cmd (con, MSG_SERVER_NOSUCH, "reregistration is not supported");
	con->destroy = 1;
	return;
    }

    /* TODO: ensure that this server is not already connected */

    if (split_line (fields, sizeof (fields) / sizeof (char *), pkt) != 3)
    {
	log ("server_login: wrong number of fields");
	send_cmd (con, MSG_SERVER_ERROR, "wrong number of fields");
	con->destroy = 1;
	return;
    }

    /* make sure this connection is coming from where they say they are */
    /* TODO: make this nonblocking for the rest of the server */
    ip = lookup_ip (fields[0]);

    if (ip != con->ip)
    {
	send_cmd (con, MSG_SERVER_NOSUCH,
		"your ip address does not match that name");
	log ("server_login(): %s does not resolve to %s", fields[0],
		my_ntoa (con->ip));
	con->destroy = 1;
	return;
    }

    FREE (con->host);
    con->host = STRDUP (fields[0]);
    con->sendernonce = STRDUP (fields[1]);
    con->compress = atoi (fields[2]);
    if (con->compress < 0 || con->compress > 9)
    {
	log ("server_login: invalid compression level (%d) from %s",
	    con->compress, con->host);
	send_cmd (con, MSG_SERVER_NOSUCH, "invalid compression level %d",
	    con->compress);
	con->compress = 0;
	con->destroy = 1;
	return;
    }
    /* take the minimum of the two values */
    if (con->compress > Compression_Level)
	con->compress = Compression_Level;

    if (!con->nonce)
    {
	if ((con->nonce = generate_nonce()) == NULL)
	{
	    send_cmd (con, MSG_SERVER_ERROR, "unable to generate nonce");
	    con->destroy = 1;
	    return;
	}

	/* respond with our own login request */
	send_cmd (con, MSG_SERVER_LOGIN, "%s %s %d", Server_Name, con->nonce,
	    con->compress);
    }

    /* send our challenge response */
    /* hash the peers nonce, our nonce and then our password */
    md5_init_ctx (&md);
    md5_process_bytes (con->sendernonce, strlen (con->sendernonce), &md);
    md5_process_bytes (con->nonce, strlen (con->nonce), &md);
    md5_process_bytes (Server_Pass, strlen (Server_Pass), &md);
    md5_finish_ctx (&md, hash);
    expand_hex (hash, 16);
    hash[32] = 0;

    /* send the response */
    send_cmd (con, MSG_SERVER_LOGIN_ACK, hash);

    /* now we wait for the peers ACK */
    log ("server_login: sent login ACK");
}

HANDLER (server_login_ack)
{
    MYSQL_RES *result;
    MYSQL_ROW row;
    struct md5_ctx md5;
    char hash[33];

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    if (con->class != CLASS_UNKNOWN)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "reregistration is not supported");
	log ("server_login_ack(): already registered!");
	return;
    }
    if (!con->nonce || !con->sendernonce)
    {
	send_cmd (con, MSG_SERVER_ERROR, "you must login first");
	log ("server_login_ack(): received ACK with no LOGIN?");
	con->destroy = 1;
	return;
    }

    /* look up the entry in our peer servers database */
    snprintf (Buf, sizeof (Buf),
	"SELECT password FROM servers WHERE name = '%s'", con->host);
    if (mysql_query (Db, Buf) != 0)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "sql error");
	sql_error ("server_login",Buf);
	con->destroy = 1;
	return;
    }

    result = mysql_store_result (Db);

    if (mysql_num_rows (result) != 1)
    {
	log ("server_login_ack(): expected 1 row returned from sql query");
	permission_denied (con);
	mysql_free_result (result);
	con->destroy = 1;
	return;
    }

    row = mysql_fetch_row (result);

    /* check the peers challenge response */
    md5_init_ctx (&md5);
    md5_process_bytes (con->nonce, strlen (con->nonce), &md5);
    md5_process_bytes (con->sendernonce, strlen (con->sendernonce), &md5);
    md5_process_bytes (row[0], strlen (row[0]), &md5); /* password for them */
    md5_finish_ctx (&md5, hash);
    expand_hex (hash, 16);
    hash[32] = 0;

    mysql_free_result (result);

    if (strcmp (hash, pkt) != 0)
    {
	log ("server_login_ack(): incorrect response for server %s",
		con->host);
	permission_denied (con);
	con->destroy = 1;
	return;
    }
		
    log ("server_login(): server %s has joined", con->host);

    notify_mods ("server %s has joined.", con->host);

    con->class = CLASS_SERVER;
#if HAVE_LIBZ
    /* set up the compression handlers for this connection */
    init_compress (con, con->compress);
#endif

    /* put this connection in the shortcut list to the server conections */
    add_server (con);

    /* synchronize our state with this server */
    synch_server (con);
}
