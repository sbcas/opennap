/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
#include "opennap.h"
#include "debug.h"

/* this function handles the PART(401) command from clients */
/* [ :<nick> ] <channel> */
HANDLER (part)
{
    CHANNEL *chan;
    USER *user;
    LIST *list;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &user) != 0)
	return;
    ASSERT (validate_user (user));

    /* find the requested channel in the user's  list */
    for (list = user->channels; list; list = list->next)
    {
	chan = list->data;
	if (!strcmp (pkt, chan->name))
	    break;
    }

    if (!list)
    {
	/* user is not on this channel */
	log ("part(): user %s is not on channel %s", user->nick, pkt);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH,
		    "You are not a member of channel %s", pkt);
	return;
    }

    if (Num_Servers)
    {
	/* NOTE: we use the MSG_CLIENT_PART(401) message instead of
	   passing MSG_SERVER_PART(407) to pass between servers because we
	   can reuse this same function for both messages easier than
	   implementing support for parsing the latter.  The 401 message
	   will be translated into a 407 for sending to end users. */
	pass_message_args (con, MSG_CLIENT_PART, ":%s %s",
		user->nick, chan->name);
    }

    user->channels = list_delete (user->channels, chan);

    /* remove user from the channel members list and notify local clients */
    part_channel (chan, user);
}
