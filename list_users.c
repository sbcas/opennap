/* Copyright (C) 2000 drscholl@hotmail.com
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include "opennap.h"
#include "debug.h"

/* packet contains: <channel> */
void
list_users (CONNECTION *con, char *pkt)
{
    CHANNEL *chan;
    int i;

    ASSERT (VALID (con));

    if (con->class != CLASS_USER)
    {
	log ("list_users(): not USER class");
	return;
    }
    chan = hash_lookup (Channels, pkt);
    if (!chan)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "channel %s does not exist", pkt);
	return;
    }
    /* make sure this user is on the channel */
    for (i = 0; i < con->user->numchannels; i++)
	if (con->user->channels[i] == chan)
	    break;
    if (i == con->user->numchannels)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "you're not on channel %s",
		chan->name);
	return;
    }

    for (i = 0; i < chan->numusers; i++)
    {
	send_cmd (con, MSG_SERVER_NAMES_LIST /* 825 */, "%s %s %d %d",
		chan->name, chan->users[i]->nick, chan->users[i]->shared,
		chan->users[i]->speed);
    }

    send_cmd (con, MSG_SERVER_NAMES_LIST_END /* 830 */, "");
}
