/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "opennap.h"
#include "debug.h"

/* handle client request to join channel */
/* [ :<nick> ] <channel> */
HANDLER (join)
{
    USER *user;
    CHANNEL *chan;
    int i;

    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &user) != 0)
	return;
    ASSERT (validate_user (user));

    /* enforce a maximum of 5 channels per user */
    if (user->numchannels > 4)
    {
	if (con->class == CLASS_USER)
	    send_cmd (con, MSG_SERVER_NOSUCH,
		"maximum number of channels is 5.");
	return;
    }

    chan = hash_lookup (Channels, pkt);
    if (!chan)
    {
	/* check if this server allows normals to create channels */
	if (Server_Flags & OPTION_STRICT_CHANNELS)
	{
	    if (con->class == CLASS_USER)
		permission_denied (con);
	    return;
	}
	chan = new_channel ();
	chan->name = STRDUP (pkt);
	chan->created = time (0);
	snprintf (Buf, sizeof (Buf), "Welcome to the %s channel.",
	    chan->name);
	chan->topic = STRDUP (Buf);
	hash_add (Channels, chan->name, chan);
	log ("join(): creating channel %s", chan->name);
    }
    else
    {
	/* ensure that this user isn't already on this channel */
	for (i = 0; i < user->numchannels; i++)
	{
	    if (user->channels[i] == chan)
	    {
		log ("user %s is already on channel %s", user->nick,
		    chan->name);
		return;
	    }
	}
    }

    ASSERT (validate_channel (chan));

    /* if local user */
    if (con->class == CLASS_USER)
    {
	/* notify other servers of this join */
	if (Num_Servers)
	{
	    pass_message_args (con, MSG_CLIENT_JOIN, ":%s %s", user->nick,
		chan->name);
	}

	/* notify client of success */
	send_cmd (con, MSG_SERVER_JOIN_ACK, "%s", chan->name);
    }

    /* add this channel to the USER channel list */
    user->channels = array_add (user->channels, &user->numchannels, chan);

    if (con->class == CLASS_USER)
    {
	/* send the client the list of current users in the channel */
	for (i = 0; i < chan->numusers; i++)
	{
	    send_cmd (con, MSG_SERVER_CHANNEL_USER_LIST, "%s %s %d %d",
		      chan->name, chan->users[i]->nick,
		      chan->users[i]->shared, chan->users[i]->speed);
	}
    }

    /* add this user to the members list */
    chan->users = REALLOC (chan->users, sizeof (USER *) * (chan->numusers + 1));
    chan->users[chan->numusers] = user;
    chan->numusers++;

    /* notify other members of the channel that this user has joined */
    for (i = 0; i < chan->numusers; i++)
    {
	/* we only send to our locally connected clients */
	if (chan->users[i]->con)
	{
	    send_cmd (chan->users[i]->con, MSG_SERVER_JOIN, "%s %s %d %d",
		      chan->name, user->nick, user->shared, user->speed);
	}
    }

    if (con->class == CLASS_USER)
    {
	/* send end of channel list message */
	/* NOTE: for some reason this is the way the napster.com servers send
	   the messages.  I'm not sure why they send the end of channel list
	   AFTER the join message for yourself */
	send_cmd (con, MSG_SERVER_CHANNEL_USER_LIST_END, "%s", chan->name);

	/* send channel topic */
	ASSERT (chan->topic != 0);
	send_cmd (con, MSG_SERVER_TOPIC, "%s %s", chan->name, chan->topic);
    }
}
