/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#ifndef WIN32
#include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

/* handle client request to join channel */
/* [ :<nick> ] <channel> */
HANDLER (join)
{
    USER *user;
    CHANNEL *chan;
    LIST *list;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &user) != 0)
	return;
    ASSERT (validate_user (user));

    /* enforce a maximum channels per user */
    if (list_count (user->channels) > Max_User_Channels)
    {
	if (ISUSER(con))
	    send_cmd (con, MSG_SERVER_NOSUCH,
		"Maximum number of channels is %d.", Max_User_Channels);
	return;
    }

    if (user->muzzled)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "Muzzled users may not join chat rooms.");
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
	if (!chan)
	    return; /* out of memory */
	chan->name = STRDUP (pkt);
	if (!chan->name)
	{
	    OUTOFMEMORY ("join");
	    FREE (chan);
	    return;
	}
	/* set the default topic */
	snprintf (Buf, sizeof (Buf), "Welcome to the %s channel.",
	    chan->name);
	chan->topic = STRDUP (Buf);
	if (!chan->topic)
	{
	    OUTOFMEMORY ("join");
	    FREE (chan->name);
	    FREE (chan);
	    return;
	}
	hash_add (Channels, chan->name, chan);
	log ("join(): creating channel %s", chan->name);
    }
    /* ensure that this user isn't already on this channel */
    else if (list_find (user->channels, chan))
    {
	log ("user %s is already on channel %s", user->nick, chan->name);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH,
		    "You are already a member of channel %s", chan->name);
	return;
    }

    ASSERT (validate_channel (chan));

    if (Num_Servers)
	pass_message_args(con,tag,":%s %s",user->nick,chan->name);

    /* if local user */
    if (ISUSER (con))
    {
	/* notify client of success */
	send_cmd (con, MSG_SERVER_JOIN_ACK, "%s", chan->name);
    }

    /* add this channel to the USER channel list */
    user->channels = list_append (user->channels, chan);

    if (ISUSER (con))
    {
	/* send the client the list of current users in the channel */
	for (list = chan->users; list; list = list->next)
	{
	    USER *chanUser = list->data;

	    ASSERT (chanUser != 0);
	    send_cmd (con, MSG_SERVER_CHANNEL_USER_LIST, "%s %s %d %d",
		      chan->name, chanUser->nick,
		      chanUser->shared, chanUser->speed);
	}
    }

    /* add this user to the members list */
    chan->users = list_append (chan->users, user);

    /* notify other members of the channel that this user has joined */
    for (list = chan->users; list; list = list->next)
    {
	/* we only send to our locally connected clients */
	if (((USER *) list->data)->local)
	{
	    send_cmd (((USER *) list->data)->con, MSG_SERVER_JOIN,
		    "%s %s %d %d",
		    chan->name, user->nick, user->shared, user->speed);
	}
    }

    if (ISUSER (con))
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
