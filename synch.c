/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"
#include "debug.h"

char *Levels[LEVEL_ELITE + 1] = {
    "Leech",
    "User",
    "Moderator",
    "Admin",
    "Elite"
};

static void
sync_user (USER * user, CONNECTION * con)
{
    LIST *list;

    ASSERT (validate_connection (con));
    ASSERT (validate_user (user));

    /* we should never tell a peer server about a user that is behind
       them */
    ASSERT (user->con != con);
    if (user->con == con)
    {
	/* this really shouldnt happen! */
	ASSERT (0);
	return;
    }

    /* send a login message for this user */
    send_cmd (con, MSG_CLIENT_LOGIN, "%s %s %d \"%s\" %d",
	      user->nick, user->pass, user->port, user->clientinfo,
	      user->speed);

    /* send the user's host */
    send_cmd (con, MSG_SERVER_USER_IP, "%s %u %hu %s", user->nick,
	      user->host, user->conport, user->server);

    /* update the user's level */
    if (user->level != LEVEL_USER)
    {
	send_cmd (con, MSG_CLIENT_SETUSERLEVEL, ":%s %s %s",
		  Server_Name, user->nick, Levels[user->level]);
    }

    /* do this before the joins so the user's already in the channel see
       the real file count */
    if (user->shared)
	send_cmd (con, MSG_SERVER_USER_SHARING, "%s %d %d", user->nick,
		  user->shared, user->libsize);

    /* send the channels this user is listening on */
    for (list = user->channels; list; list = list->next)
    {
	send_cmd (con, MSG_CLIENT_JOIN, ":%s %s",
		  user->nick, ((CHANNEL *) list->data)->name);
    }
}

static void
sync_chan (CHANNEL *chan, CONNECTION *con)
{
    if (chan->level != LEVEL_USER)
	send_cmd (con, MSG_CLIENT_CHANNEL_LEVEL, ":%s %s %s",
		Server_Name, chan->name, Levels[chan->level]);
}

void
synch_server (CONNECTION * con)
{
    ASSERT (validate_connection (con));

    log ("synch_server(): syncing");

    /* send our peer server a list of all users we know about */
    hash_foreach (Users, (hash_callback_t) sync_user, con);
    /* sync the channel level */
    hash_foreach (Channels, (hash_callback_t) sync_chan, con);

    log ("synch_server(): done");
}
