/* Copyright (C) 2000 drscholl@users. sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#ifndef WIN32
#include <unistd.h>
#endif
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
    int i, len;

    ASSERT (validate_channel (chan));
    ASSERT (validate_user (user));

    /* remove this user from the channel list */
    chan->users = array_remove (chan->users, &chan->numusers, user);

    /* notify other members of this channel that this user has parted */
    snprintf (Buf+4,sizeof(Buf)-4,"%s %s %d %d",
	    chan->name, user->nick, user->shared, user->speed);
    set_tag(Buf,MSG_SERVER_PART);
    len=strlen(Buf+4);
    set_len(Buf,len);
    for (i = 0; i < chan->numusers; i++)
    {
	/* we only notify local clients */
	if (chan->users[i]->local)
	{
	    ASSERT (validate_user (chan->users[i]));
	    ASSERT (validate_connection (chan->users[i]->con));
	    queue_data (chan->users[i]->con, Buf, len + 4);
	}
    }

    /* if there are no users left in this channel, destroy it */
    if (chan->numusers == 0)
    {
	log("part_channel(): destroying channel %s", chan->name);
	hash_remove (Channels, chan->name);
    }
}
