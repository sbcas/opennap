/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <mysql.h>
#include "opennap.h"
#include "debug.h"

extern MYSQL *Db;

/* packet contains: <checksum> <filesize> */
HANDLER (resume)
{
    char *fields[2];
    MYSQL_RES *result;
    MYSQL_ROW row;
    USER *user;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    CHECK_USER_CLASS ("resume");

    if (split_line (fields, sizeof (fields) / sizeof (char *), pkt) != 2)
    {
	log ("resume(): wrong number of fields");
	return;
    }
    
    /* search the database for a list of all files which match this request */
    snprintf (Buf, sizeof (Buf), "SELECT * FROM library WHERE md5 = %s && size = %s",
	fields[0], fields[1]);
    if (mysql_query (Db, Buf) != 0)
    {
	sql_error ("resume", Buf);
	return;
    }

    result = mysql_store_result (Db);
    while ((row = mysql_fetch_row (result)) != NULL)
    {
	user = hash_lookup (Users, row[IDX_NICK]);
	ASSERT (user != 0);
	send_cmd (con, MSG_SERVER_RESUME_MATCH, "%s %lu %d %s %s %s %hu",
	    row[IDX_NICK], user->host, user->port, row[IDX_FILENAME],
	    row[IDX_MD5], row[IDX_SIZE], user->speed);
    }

    send_cmd (con, MSG_SERVER_RESUME_MATCH_END, "");

    mysql_free_result (result);
}
