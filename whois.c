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

/* this is nasty but a necessary evil to avoid using a static buffer */
static char *
append_string (char *in, const char *fmt, ...)
{
    va_list ap;

    va_start (ap, fmt);
    vsnprintf (Buf, sizeof (Buf), fmt, ap);
    va_end (ap);
    if (!in)
	return STRDUP (Buf);
    else
    {
	int len = strlen (in);

	in = REALLOC (in, len + strlen (Buf) + 1);
	strcpy (in + len, Buf);
	return in;
    }
}

/* 604 <user> */
HANDLER (whois)
{
    USER *sender, *user;
    time_t online;
    LIST *chan;
    USERDB *db;
    char *cap;
    char *rsp = 0;

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
	    nosuchuser (con);
	return;
    }

    ASSERT (validate_user (user));

    online = (int) (Current_Time - user->connected);

    rsp = append_string (rsp, "%s", user->nick);
    rsp = append_string (rsp, " \"%s\"", Levels[user->level]);
    rsp = append_string (rsp, " %d", (int) online);
    rsp = append_string (rsp, " \" ");
    /* always show channel membership to privileged users */
    if (!user->cloaked || sender->level > LEVEL_USER)
    {
	for (chan = user->channels; chan; chan = chan->next)
	{
	    if((((CHANNEL*)chan->data)->flags & ON_CHANNEL_PRIVATE)==0)
		rsp = append_string (rsp, "%s ", ((CHANNEL *) chan->data)->name);
	}
    }
    rsp = append_string (rsp, "\"");	/* terminate the channel list */

    if (user->muzzled)
	cap = "Muzzled";
    else if (user->cloaked && sender->level > LEVEL_USER)
	cap = "Cloaked";	/* show cloaked state to privileged users */
    else
	cap = "Active";
    rsp = append_string (rsp, " \"%s\"", cap);
    rsp = append_string (rsp, " %d %d %d %d", user->shared, user->downloads,
			 user->uploads, user->speed);
    rsp = append_string (rsp, " \"%s\"", user->clientinfo);

    /* moderators and above see some additional information */
    if (sender->level > LEVEL_USER)
    {
	db = hash_lookup (User_Db, user->nick);
	rsp = append_string (rsp, " %d %d %s %d %d",
			     user->totaldown, user->totalup,
			     my_ntoa (user->host),
			     user->conport, user->port);
#if EMAIL
#define EmailAddr(db) db?db->email:"unknown"
#else
#define EmailAddr(db) "unknown"
#endif
	rsp = append_string (rsp, " %s", EmailAddr(db));
    }
    /* admins and above see the server the user is connected to.  this is
       only admin+ since the windows client would likely barf if present.
       i assume that admin+ will use another client such as BWap which
       understands the extra field */
    if (sender->level > LEVEL_MODERATOR)
	rsp =
	    append_string (rsp, " %s",
			   user->server ? user->server : Server_Name);
    send_user (sender, MSG_SERVER_WHOIS_RESPONSE, "%s", rsp);
    FREE (rsp);

    /* notify privileged users when someone requests their info */
    if (user->level >= LEVEL_MODERATOR && sender != user)
    {
	ASSERT (validate_connection (user->con));

	send_user (user, MSG_SERVER_NOSUCH,
		   "%s has requested your info", con->user->nick);
    }
}
