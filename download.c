/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <unistd.h>
#include <stdio.h>
#include <mysql.h>
#include "opennap.h"
#include "debug.h"

extern MYSQL *Db;

/* handle client request for download of a file */
/* <nick> <filename> */
HANDLER (download)
{
    char *fields[2];
    USER *user;
    MYSQL_RES *result;
    MYSQL_ROW row;
    int numrows;
    char path[256];

    ASSERT (VALID (con));

    CHECK_USER_CLASS ("download");

    if (split_line (fields, sizeof (fields) / sizeof (char *), pkt) != 2)
    {
	log ("download(): malformed user request");
	return;
    }
    user = hash_lookup (Users, fields[0]);
    if (!user)
    {
	nosuchuser (con, fields[0]);
	return;
    }
    ASSERT (VALID (user));

    fudge_path(fields[1], path);

    /* retrieve file info from the database */
    snprintf (Buf, sizeof (Buf),
	      "SELECT * FROM library WHERE owner = '%s' && filename = '%s'",
	      user->nick, path);
    if (mysql_query (Db, Buf) != 0)
    {
	sql_error ("download", Buf);
	return;
    }
    result = mysql_store_result (Db);
    numrows = mysql_num_rows (result);
    if (numrows != 1)
    {
	log ("download(): fatal error, query returned more than 1 row");
	mysql_free_result (result);
	return;
    }

    row = mysql_fetch_row (result);
    ASSERT (row != 0);

    /* send the requestor an ACK */
    send_cmd (con, MSG_SERVER_DOWNLOAD_ACK, "%s %lu %d \"%s\" %s %d",
	      user->nick, user->host, user->port, row[IDX_FILENAME],
	      row[IDX_MD5], user->speed);

    /* look up the target user */
    user = hash_lookup (Users, row[IDX_NICK]);
    if (!user)
    {
	log ("download(): could not find user %s", row[IDX_NICK]);
	mysql_free_result (result);
	return;
    }

    mysql_free_result (result);

    /* send a message to the requestee */
    log ("download(): sending upload request to %s", user->nick);

    /* if the requestee is a local user, send the request directly */
    if (user->con)
    {
	send_cmd (user->con, MSG_SERVER_UPLOAD_REQUEST, "%s \"%s\"",
		con->user->nick, fields[1]);
    }
    else
    {
	/* otherwise pass it to our peer servers for delivery */
	send_cmd (user->serv, MSG_SERVER_UPLOAD_REQUEST, ":%s %s \"%s\"",
		con->user->nick, fields[0], fields[1]);
    }

    /* this should probably be done when the clients ack the download request
       instead, since the uploader could conceivable not allow the connection */

    user->uploads++;
    con->user->downloads++;
}
