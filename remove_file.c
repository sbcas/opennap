/* Copyright (C) 2000 drscholl@sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <mysql.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

extern MYSQL *Db;

/* packet contains: [ :<user> ] <filename> */
void
remove_file (CONNECTION *con, char *pkt)
{
    USER *user;
    MYSQL_RES	*result;
    MYSQL_ROW	row;

    ASSERT (VALID (con));

    if (pop_user (con, &pkt, &user) != 0)
	return;

    /* if a local user, pass this message to our peer servers */
    if (con->class == CLASS_USER)
	pass_message_args (con, MSG_CLIENT_REMOVE_FILE, ":%s %s",
	    user->nick, pkt);

    /* need to pull the file size from the database to update the statistics */
    snprintf (Buf, sizeof (Buf), "SELECT size FROM library WHERE owner = '%s' && filename = '%s'",
	user->nick, pkt);
    if (mysql_query (Db, Buf) != 0)
    {
	sql_error ("remove_file", Buf);
	return;
    }
    result = mysql_store_result (Db);
    if (mysql_num_rows (result) == 1)
    {
	row = mysql_fetch_row (result);

	/* avoid rounding errors by first subtracting the old value */
	Num_Gigs -= user->libsize / 1024;
	user->libsize -= atoi (row[0]) / 1024;
	Num_Gigs += user->libsize / 1024;
    }
    else
	log ("remove_file(): expected 1 row returned from query");

    mysql_free_result (result);

    Num_Files--;
    user->shared--;

    snprintf (Buf, sizeof (Buf), "DELETE FROM library WHERE owner = '%s' && filename = '%s'",
	user->nick, pkt);
    if (mysql_query (Db, Buf) != 0)
    {
	sql_error ("remove_file", Buf);
	return;
    }
}
