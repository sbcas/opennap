/* Copyright (C) 2000 drscholl@sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <mysql.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "opennap.h"
#include "debug.h"

extern MYSQL *Db;

void
browse (CONNECTION * con, char *pkt)
{
    MYSQL_RES *result;
    MYSQL_ROW row;
    int i, numrows;
    USER *user;

    ASSERT (VALID (con));
    if (con->class != CLASS_USER)
    {
	log ("browse(): only USER class may execute this command");
	return;
    }
    user = hash_lookup (Users, pkt);
    if (!user)
    {
	nosuchuser (con, pkt);
	return;
    }

    snprintf (Buf, sizeof (Buf), "SELECT * FROM library WHERE owner = '%s'",
	      user->nick);
    if (mysql_query (Db, Buf) != 0)
    {
	sql_error ("browse", Buf);
	return;
    }
    result = mysql_store_result (Db);
    if (result == 0)
    {
	log ("browse(): sql query returned NULL");
	return;
    }
    numrows = mysql_num_rows (result);
    log ("browse(): search returned %d rows", numrows);
    for (i = 0; i < numrows; i++)
    {
	row = mysql_fetch_row (result);
	send_cmd (con, MSG_SERVER_BROWSE_RESPONSE,
	    "%s \"%s\" %s %s %s %s %s",
	    row[IDX_NICK],	/* nick */
	    row[IDX_FILENAME],	/* filename */
	    row[IDX_MD5],	/* md5 */
	    row[IDX_SIZE],	/* size */
	    row[IDX_BITRATE],	/* bitrate */
	    row[IDX_FREQ],	/* sample rate */
	    row[IDX_LENGTH] /* duration */ );
    }
    mysql_free_result (result);

    /* send end of browse list message */
    send_cmd (con, MSG_SERVER_BROWSE_END, "%s", user->nick);
}
