/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"
#include "debug.h"

/* packet contains: <channel> */
HANDLER (list_users)
{
    CHANNEL *chan;
    LIST *list;
    USER *chanUser;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("list_users");
    chan = hash_lookup (Channels, pkt);
    if (!chan)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "channel %s does not exist", pkt);
	return;
    }
    ASSERT (validate_channel (chan));
    /* make sure this user is on the channel */
    if (list_find (con->user->channels, chan) == 0)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "you're not on channel %s",
	    chan->name);
	return;
    }

    for (list = chan->users; list; list = list->next)
    {
	chanUser = list->data;
	send_cmd (con, MSG_SERVER_NAMES_LIST /* 825 */, "%s %s %d %d",
		chan->name, chanUser->nick, chanUser->shared, chanUser->speed);
    }

    send_cmd (con, MSG_SERVER_NAMES_LIST_END /* 830 */, "");
}
