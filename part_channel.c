/* Copyright (C) 2000 drscholl@users. sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#ifndef WIN32
#include <unistd.h>
#endif
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

/* remove this user from the channel list */
static LIST *
channel_remove (CHANNEL * chan, USER * user)
{
    LIST **list, *tmpList;
    CHANUSER *chanUser;

    for (list = &chan->users; *list; list = &(*list)->next)
    {
	chanUser = (*list)->data;
	ASSERT (chanUser->magic == MAGIC_CHANUSER);
	if (chanUser->user == user)
	{
	    tmpList = *list;
	    *list = (*list)->next;
	    FREE (tmpList);
	    FREE (chanUser);
	    break;
	}
    }
    return chan->users;
}

/* remove `user' from channel `chan' */
/* this function only removes the user entry from the channel list and
   notifies any local users of the departure.  the server-server message
   happens in the caller of this routine since in the QUIT case we don't
   send PART messages across servers when a client quits */
void
part_channel (CHANNEL * chan, USER * user)
{
    int len;
    CHANUSER *chanUser;
    LIST *list;

    ASSERT (validate_channel (chan));
    ASSERT (validate_user (user));

    chan->users = channel_remove (chan, user);
    if (chan->users)
    {
	/* notify other members of this channel that this user has parted */
	len = form_message (Buf, sizeof (Buf), MSG_SERVER_PART,
			    "%s %s %d %d", chan->name, user->nick,
			    user->shared, user->speed);
	for (list = chan->users; list; list = list->next)
	{
	    /* we only notify local clients */
	    chanUser = list->data;
	    ASSERT (chanUser->magic == MAGIC_CHANUSER);
	    if (ISUSER (chanUser->user->con))
	    {
		if (!user->cloaked
		    || chanUser->user->level >= LEVEL_MODERATOR)
		    queue_data (chanUser->user->con, Buf, len);
	    }
	}
    }
    /* if there are no users left in this channel, destroy it */
    else if (chan->flags & ON_CHANNEL_USER)
    {
	log ("part_channel(): destroying channel %s", chan->name);
	hash_remove (Channels, chan->name);
    }
}
