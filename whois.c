/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.
 
   $Id$ */

#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <mysql.h>
#include "opennap.h"
#include "debug.h"

extern MYSQL *Db;

#define WHOIS_FMT "%s \"%s\" %d \"%s\" \"Active\" %d %d %d %d \"%s\""

/* packet contains: <user> */
HANDLER (whois)
{
    USER *user;
    int i, l;
    char *chanlist;
    time_t online;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("whois");
    user = hash_lookup (Users, pkt);
    if (!user)
    {
	MYSQL_RES *result;
	MYSQL_ROW row;

	/* check to see if this is a registered nick */
	snprintf (Buf, sizeof (Buf),
	    "SELECT level,lastseen FROM accounts WHERE nick LIKE '%s'", pkt);
	if (mysql_query (Db, Buf) != 0)
	{
	    sql_error ("whois", Buf);
	    send_cmd (con, MSG_SERVER_NOSUCH, "db error");
	    return;
	}
	result = mysql_store_result (Db);
	if (mysql_num_rows (result) > 0)
	{
	    row = mysql_fetch_row (result);
	    send_cmd (con, MSG_SERVER_WHOWAS, "%s %s %s", pkt, row[0], row[1]);
	}
	else
	    nosuchuser (con, pkt);
	mysql_free_result (result);
	return;
    }

    ASSERT (validate_user (user));

    chanlist = STRDUP (" ");

    /* build the channel list this user belongs to */
    for (i = 0; i < user->numchannels; i++)
    {
	l = strlen (chanlist);
	chanlist = REALLOC (chanlist, l + strlen (user->channels[i]->name) + 2);
	strcat (chanlist, user->channels[i]->name);
	strcat (chanlist, " ");
    }

    online = (int) (time (0) - user->connected);
    if (con->user->level < LEVEL_MODERATOR)
    {
	send_cmd (con, MSG_SERVER_WHOIS_RESPONSE,
		WHOIS_FMT, user->nick, Levels[user->level],
		online,
		chanlist, user->shared, user->downloads, user->uploads,
		user->speed, user->clientinfo);
    }
    else
    {
	send_cmd (con, MSG_SERVER_WHOIS_RESPONSE,
		"%s \"%s\" %d \"%s\" \"Active\" %d %d %d %d \"%s\" %d %d %s %d %d %s",
		user->nick, Levels[user->level], online, chanlist, user->shared,
		user->downloads, user->uploads, user->speed, user->clientinfo,
		user->totalup, user->totaldown, my_ntoa (user->host),
		user->conport, user->port,
		user->email ? user->email : "unknown");
    }
    FREE (chanlist);
}
