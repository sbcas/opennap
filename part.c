/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include "opennap.h"
#include "debug.h"

/* this function handles the PART(401) command from clients */
/* [ :<nick> ] <channel> */
HANDLER (part)
{
    int i;
    CHANNEL *chan = 0;
    USER *user;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &user) != 0)
	return;
    ASSERT (validate_user (user));

    /* find the requested channel in the user's  list */
    for (i = 0; i < user->numchannels; i++)
    {
	ASSERT (validate_channel (user->channels[i]));
	if (strcmp (pkt, user->channels[i]->name) == 0)
	{
	    chan = user->channels[i];
	    break;
	}
    }

    if (!chan)
    {
	/* user is not on this channel */
	log ("part(): user %s is not on channel %s", user->nick, pkt);
	if (con->class == CLASS_USER)
	    send_cmd (con, MSG_SERVER_NOSUCH,
		    "you are not a member of channel %s", pkt);
	return;
    }

    user->channels = array_remove (user->channels, &user->numchannels, chan);

    /* if local, notify our peer servers that this client has parted */
    if (con->class == CLASS_USER && Num_Servers)
    {
	/* NOTE: we use the MSG_CLIENT_PART(401) message instead of
	   passing MSG_SERVER_PART(407) to pass between servers because we
	   can reuse this same function for both messages easier than
	   implementing support for parsing the latter.  The 401 message
	   will be translated into a 407 for sending to end users. */
	pass_message_args (con, MSG_CLIENT_PART, ":%s %s",
		user->nick, chan->name);
    }

    /* remove user from the channel members list and notify local clients */
    part_channel (chan, user);
}
