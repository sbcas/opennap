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
    char cmd[256];

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
		  ((CHANNEL *) chan->data)->name);
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

    snprintf (cmd, sizeof (cmd),
	      "%s \"%s\" %d \"%s\" \"%s\" %d %d %d %d \"%s\"",
	      user->nick, Levels[user->level],
	      (int) online, chanlist,
	      user->muzzled ? "Muzzled" : "Active",
	      user->shared, user->downloads,
	      user->uploads, user->speed, user->clientinfo);
    /* moderators and above see some additional information */
    if (sender->level > LEVEL_USER)
    {
	db = hash_lookup (User_Db, user->nick);
	snprintf (cmd + strlen (cmd), sizeof (cmd) - strlen (cmd),
		  " %d %d %s %d %d %s", user->totaldown, user->totalup,
		  my_ntoa (user->host), user->conport, user->port,
		  db ? db->email : "unknown");
    }
    /* admins and above see the server the user is connected to.  this is
       only admin+ since the windows client would likely barf if present.
       i assume that admin+ will use another client such as BWap which
       understands the extra field */
    if (sender->level > LEVEL_MODERATOR)
	snprintf (cmd + strlen (cmd), sizeof (cmd) - strlen (cmd), " %s",
		  user->server ? user->server : Server_Name);
    send_user (sender, MSG_SERVER_WHOIS_RESPONSE, "%s", cmd);
    FREE (chanlist);

    /* notify privileged users when someone requests their info */
    if (user->level >= LEVEL_MODERATOR && sender != user)
    {
	ASSERT (validate_connection (user->con));

	send_user (user, MSG_SERVER_NOSUCH,
		   "%s has requested your info", con->user->nick);
    }
}

/* 831 */
HANDLER (global_user_list)
{
    (void) tag;
    (void) len;
    (void) pkt;
    ASSERT(validate_connection(con));
    CHECK_USER_CLASS("global_user_list");
    if(con->user->level<LEVEL_MODERATOR)
    {
	permission_denied(con);
	return;
    }
    /*TODO: still dont know what the numeric and format for the server
      response are */
    send_cmd(con,832,"a b c d e f");
    send_cmd(con,831,"");
}
