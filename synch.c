/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <unistd.h>
#include <mysql.h>
#include "opennap.h"
#include "debug.h"

extern MYSQL *Db;

char *Levels[LEVEL_ELITE+1] = {
    "Leech",
    "User",
    "Moderator",
    "Admin",
    "Elite"
};

static void
synch_user (void *data, void *funcdata)
{
    USER *user = (USER *) data;
    CONNECTION *con = (CONNECTION *) funcdata;
    int i, n;
    MYSQL_RES *result;
    MYSQL_ROW row;

    ASSERT (VALID (user));

    /* send a login message for this user */
    send_cmd (con, MSG_CLIENT_LOGIN, "%s - %d \"%s\" %d",
	    user->nick, user->port, user->clientinfo, user->speed);

    /* update the user's level */
    if (user->level > LEVEL_USER)
    {
	send_cmd (con, MSG_CLIENT_SETUSERLEVEL, ":%s %s %s",
	    Server_Name, user->nick, Levels[user->level]);
    }

    /* send the channels this user is listening on */
    for (i = 0; i < user->numchannels; i++)
    {
	send_cmd (con, MSG_CLIENT_JOIN, ":%s %s",
		user->nick, user->channels[i]->name);
    }

    /* find the files that this user has shared */
    snprintf (Buf, sizeof (Buf), "SELECT * FROM library WHERE owner = '%s'",
	    user->nick);
    if (mysql_query (Db, Buf) != 0)
    {
	sql_error ("synch_user", Buf);
	return;
    }
    result = mysql_store_result (Db);
    n = mysql_num_rows (result);
    for (i = 0; i < n; i++)
    {
	mysql_data_seek (result, i);
	row = mysql_fetch_row (result);
	send_cmd (con, MSG_CLIENT_ADD_FILE, ":%s \"%s\" %s %s %s %s %s",
		row[IDX_NICK], row[IDX_FILENAME], row[IDX_MD5],
		row[IDX_SIZE], row[IDX_BITRATE], row[IDX_FREQ],
		row[IDX_LENGTH]);
    }
    mysql_free_result (result);

    /* in order to avoid too much data building up in memory, flush the
       info for this user here */
    send_queued_data (con);
}

void
synch_server (CONNECTION *con)
{
    /* send our peer server a list of all users we know about */
    hash_foreach (Users, synch_user, (void *) con);
}
