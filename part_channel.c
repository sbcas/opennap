/* Copyright (C) 2000 drscholl@users. sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include "opennap.h"
#include "debug.h"

/* remove `user' from channel `chan' */
/* this function only removes the user entry from the channel list and
   notifies any local users of the departure.  the server-server message
   happens in the caller of this routine since in the QUIT case we don't
   send PART messages across servers when a client quits */
void
part_channel (CHANNEL * chan, USER * user)
{
    int i;

    ASSERT (VALID (chan));
    ASSERT (VALID (user));
    ASSERT (VALID (chan->users));

    /* remove this user from the channel list */
    for (i = 0; i < chan->numusers; i++)
    {
	if (chan->users[i] == user)
	    break;
    }
    if (i == chan->numusers)
    {
	log ("part_channel(): error, channel %s has no link to user %s",
	    chan->name, user->nick);
	return; /* bail out since what is below requires this condition to
		   be false */
    }

    /* shift down the rest of the user entries */
    if (i < chan->numusers -  1)
	memmove (&chan->users[i], &chan->users[i + 1],
		 sizeof (USER *) * (chan->numusers - i - 1));
    chan->numusers--;
    chan->users = REALLOC (chan->users, sizeof (USER *) * chan->numusers);

    /* notify other members of this channel that this user has parted */
    for (i = 0; i < chan->numusers; i++)
    {
	/* we only notify local clients */
	if (chan->users[i]->con)
	{
	    ASSERT (VALID (chan->users[i]));
	    ASSERT (VALID (chan->users[i]->con));
	    send_cmd (chan->users[i]->con, MSG_SERVER_PART, "%s %s %d %d",
		      chan->name, user->nick, user->shared, user->speed);
	}
    }

    /* if there are no users left in this channel, destroy it */
    if (chan->numusers == 0)
    {
	log("part_channel(): destroying channel %s", chan->name);
	hash_remove (Channels, chan->name);
    }
}
