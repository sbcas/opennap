/* Copyright (C) 1999 drscholl@hotmail.com
   This is free software distributed under the terms of the
   GNU Public License. */

#include <netdb.h>
#include <unistd.h>
#include <mysql.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include "opennap.h"
#include "debug.h"
#include "global.h"
#include "md5.h"

extern MYSQL *Db;

/* process a request to establish a peer server connection */
/* <name> <nonce> */
void
server_login (CONNECTION *con, char *pkt)
{
    char *fields[2];
    struct hostent *he;
    struct in_addr ip;
    MD5_CTX md5;
    char hash[33];

    ASSERT (VALID (con));
    if (con->class != CLASS_UNKNOWN)
    {
	log ("server_login(): reregistration is not supported");
	remove_connection (con);
	return;
    }

    /* TODO: ensure that this server is not already connected */

    if (split_line (fields, sizeof (fields) / sizeof (char *), pkt) != 2)
    {
	log ("server_login(): wrong number of feilds");
	remove_connection (con);
	return;
    }

    /* make sure this connection is coming from where they say they are */
    /* TODO: make this nonblocking for the rest of the server */
    log ("server_login(): doing reverse lookup");
    he = gethostbyname (fields[0]);
    if (!he)
    {
	log ("server_login(): unable to find ip address for %s", fields[0]);
	remove_connection (con);
	endhostent();
	return;
    }

    memcpy (&ip, &he->h_addr[0], he->h_length);

    if (ip.s_addr != con->ip)
    {
	log ("server_login(): dns name does not match ip for connection (%s != %s)",
		inet_ntoa (ip), he->h_name);
	remove_connection (con);
	endhostent();
	return;
    }

    endhostent();

    FREE (con->host);
    con->host = STRDUP (fields[0]);

    con->sendernonce = STRDUP (fields[1]);

    if (!con->nonce)
    {
	if ((con->nonce = generate_nonce()) == NULL)
	{
	    remove_connection (con);
	    return;
	}

	/* respond with our own login request */
	send_cmd (con, MSG_SERVER_LOGIN, "%s %s", Server_Name, con->nonce);
    }

    /* send our challenge response */
    /* hash the peers nonce, our nonce and then our password */
    MD5Init (&md5);
    MD5Update (&md5, (uchar*)con->sendernonce, (uint)strlen (con->sendernonce));
    MD5Update (&md5, (uchar*)con->nonce, (uint)strlen (con->nonce));
    MD5Update (&md5, (uchar*)Server_Pass, (uint)strlen (Server_Pass));
    MD5Final ((uchar*)hash, &md5);
    expand_hex (hash, 16);
    hash[32] = 0;

    /* send the response */
    send_cmd (con, MSG_SERVER_LOGIN_ACK, hash);

    /* now we wait for the peers ACK */
}

void
server_login_ack (CONNECTION *con, char *pkt)
{
    MYSQL_RES *result;
    MYSQL_ROW row;
    MD5_CTX md5;
    char hash[33];

    ASSERT (VALID (con));

    if (con->class != CLASS_UNKNOWN)
    {
	log ("server_login_ack(): already registered!");
	return;
    }
    if (!con->nonce || !con->sendernonce)
    {
	log ("server_login_ack(): received ACK with no LOGIN?");
	remove_connection (con); /* FATAL */
	return;
    }

    /* look up the entry in our peer servers database */
    snprintf (Buf, sizeof (Buf), "SELECT password FROM servers WHERE name = '%s'",
	    con->host);
    if (mysql_query (Db, Buf) != 0)
    {
	sql_error ("server_login",Buf);
	remove_connection (con);
	return;
    }

    result = mysql_store_result (Db);

    if (mysql_num_rows (result) != 1)
    {
	log ("server_login_ack(): expected 1 row returned from sql query");
	mysql_free_result (result);
	remove_connection (con);
	return;
    }

    row = mysql_fetch_row (result);

    /* check the peers challenge response */
    MD5Init (&md5);
    MD5Update (&md5, (uchar *) con->nonce, (uint) strlen (con->nonce));
    MD5Update (&md5, (uchar *) con->sendernonce, (uint) strlen (con->sendernonce));
    MD5Update (&md5, (uchar *) row[0], (uint) strlen (row[0])); /* password for them */
    MD5Final ((uchar *) hash, &md5);
    expand_hex (hash, 16);
    hash[32] = 0;

    mysql_free_result (result);

    if (strcmp (hash, pkt) != 0)
    {
	log ("server_login_ack(): incorrect response for server %s",
		con->host);
	remove_connection (con);
	return;
    }
		
    log ("server_login(): server %s has joined", con->host);

    con->class = CLASS_SERVER;

    /* put this connection in the shortcut list to the server conections */
    add_server (con);

    /* synchronize our state with this server */
    synch_server (con);
}
