/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.
 
   $Id$ */

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

#define WHOIS_FMT "%s \"%s\" %d \"%s\" \"Active\" %d %d %d %d \"%s\""

/* 604 <user> */
HANDLER (whois)
{
    USER *sender, *user;
    int l;
    char *chanlist;
    time_t online;
    LIST *chan;
    USERDB *db;

    (void) tag;
    (void) len;
    CHECK_USER_CLASS ("whois");
    sender = con->user;
    ASSERT (validate_connection (con));
    user = hash_lookup (Users, pkt);
    if (!user)
    {
	/* check to see if this is a registered nick */
	db = hash_lookup (User_Db, pkt);
	if (db)
	    send_cmd (con, MSG_SERVER_WHOWAS, "%s %s %d", db->nick,
		      Levels[db->level], db->lastSeen);
	else
	    nosuchuser (con, pkt);
	return;
    }

    ASSERT (validate_user (user));

    /* build the channel list this user belongs to */
    Buf[0] = 0;
    for (chan = user->channels; chan; chan = chan->next)
    {
	l = strlen (Buf);
	snprintf (Buf + l, sizeof (Buf) - l, " %s",
		((CHANNEL*)chan->data)->name);
    }
    if (!Buf[0])
    {
	/* the windows client doesn't seem to be able to parse an empty
	   string so we ensure that there is always one space in the string
	   returned to the client */
	Buf[0] = ' ';
	Buf[1] = 0;
    }
    chanlist = STRDUP (Buf);

    online = (int) (Current_Time - user->connected);
    if (sender->level < LEVEL_MODERATOR)
    {
	send_user (sender, MSG_SERVER_WHOIS_RESPONSE,
		WHOIS_FMT, user->nick, Levels[user->level],
		online, chanlist, user->shared, user->downloads, user->uploads,
		user->speed, user->clientinfo);
    }
    else if (sender->level > LEVEL_MODERATOR)
    {
	/* we show admins the server which a user is connected to */
	send_user (sender, MSG_SERVER_WHOIS_RESPONSE,
		"%s \"%s\" %d \"%s\" \"Active\" %d %d %d %d \"%s\" %d %d %s %d %d %s %s",
		user->nick, Levels[user->level], online, chanlist, user->shared,
		user->downloads, user->uploads, user->speed, user->clientinfo,
		user->totaldown, user->totalup, my_ntoa (user->host),
		user->conport, user->port,
		user->email ? user->email : "unknown",
		user->server ? user->server : Server_Name);
    }
    else
    {
	send_user (sender, MSG_SERVER_WHOIS_RESPONSE,
		"%s \"%s\" %d \"%s\" \"Active\" %d %d %d %d \"%s\" %d %d %s %d %d %s",
		user->nick, Levels[user->level], online, chanlist, user->shared,
		user->downloads, user->uploads, user->speed, user->clientinfo,
		user->totaldown, user->totalup, my_ntoa (user->host),
		user->conport, user->port,
		user->email ? user->email : "unknown");
    }
    FREE (chanlist);

    /* notify privileged users when someone requests their info */
    if (user->level >= LEVEL_MODERATOR)
    {
	ASSERT (validate_connection (user->con));

	send_user (user, MSG_SERVER_NOSUCH,
		"%s has requested your info", con->user->nick);
    }
}
