/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <mysql.h>
#include <stdlib.h>
#include <stdio.h>
#include "opennap.h"
#include "debug.h"

extern MYSQL *Db;

/* packet contains: [ :<user> ] <filename> */
HANDLER (remove_file)
{
    USER *user;
#if MINIDB
    int i;
#else
    MYSQL_RES	*result;
    MYSQL_ROW	row;
#endif /* MINIDB */
    int fsize;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &user) != 0)
	return;

    /* if a local user, pass this message to our peer servers */
    if (con->class == CLASS_USER)
	pass_message_args (con, MSG_CLIENT_REMOVE_FILE, ":%s %s",
	    user->nick, pkt);

#if MINIDB
    for (i = 0; i < File_Table_Count; i++)
    {
	if (user == File_Table[i]->user &&
		!strcmp (pkt, File_Table[i]->filename))
	{
	    /* subtract the file size from the user and global counts */
	    fsize = File_Table[i]->size / 1024; /* in kbytes */
	    user->libsize -= fsize;
	    Num_Gigs -= fsize;
	    free_elem (File_Table[i]);
	    File_Table_Count--;
	    /* if there are other entries, move the last one to fill this
	       spot, since we don't particularly care about order */
	    if (File_Table_Count > 0)
		File_Table[i] = File_Table[File_Table_Count];
	    break;
	}
    }
#else
    /* need to pull the file size from the database to update the statistics */
    snprintf (Buf, sizeof (Buf),
	    "SELECT size FROM library WHERE owner = '%s' && filename = '%s'",
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

	fsize = atoi (row[0]) / 1024; /* kB */
	user->libsize -= fsize;
	Num_Gigs -= fsize;
    }
    else
	log ("remove_file(): expected 1 row returned from query");

    mysql_free_result (result);

    snprintf (Buf, sizeof (Buf),
	    "DELETE FROM library WHERE owner = '%s' && filename = '%s'",
	user->nick, pkt);
    if (mysql_query (Db, Buf) != 0)
	sql_error ("remove_file", Buf);
#endif /* MINIDB */

    Num_Files--;
    user->shared--;
}
