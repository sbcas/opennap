/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#ifdef WIN32
#include <windows.h>
#endif
#include <mysql.h>
#include <stdlib.h>
#include <stdio.h>
#include "opennap.h"
#include "debug.h"

extern MYSQL *Db;

/* packet contains: [ :<user> ] <filename> */
HANDLER (remove_file)
{
    USER	*user;
    MYSQL_RES	*result;
    MYSQL_ROW	row;
    int		fsize;
    char	path[256];

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &user) != 0)
	return;

    /* if a local user, pass this message to our peer servers */
    if (con->class == CLASS_USER)
	pass_message_args (con, MSG_CLIENT_REMOVE_FILE, ":%s %s",
	    user->nick, pkt);

    /* need to pull the file size from the database to update the statistics */
    fudge_path (pkt, path, sizeof (path));
    snprintf (Buf, sizeof (Buf),
	    "SELECT size FROM library WHERE owner='%s' && filename='%s'",
	    user->nick, path);
    if (mysql_query (Db, Buf) != 0)
    {
	sql_error ("remove_file", Buf);
	return;
    }
    result = mysql_store_result (Db);
    if ((fsize = mysql_num_rows (result)) != 1)
    {
	row = mysql_fetch_row (result);
	if (!row)
	{
	    log ("remove_file(): mysql_fetch_row() returned NULL");
	    mysql_free_result (result);
	    return;
	}

	fsize = atoi (row[0]) / 1024; /* kB */
	user->libsize -= fsize;
	Num_Gigs -= fsize;
	ASSERT (Num_Files > 0);
	Num_Files--;
	user->shared--;

	snprintf (Buf, sizeof (Buf),
		"DELETE FROM library WHERE owner='%s' && filename='%s'",
		user->nick, path);
	if (mysql_query (Db, Buf) != 0)
	    sql_error ("remove_file", Buf);
    }
    else
	log ("remove_file(): expected 1 row returned from query");

    mysql_free_result (result);
}
