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
    USER *user, *chanUser;
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
	log ("join(): %s reached max channel count (%d)", user->nick,
	     Max_User_Channels);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH,
		      "Maximum number of channels is %d.", Max_User_Channels);
	return;
    }

    if (user->muzzled)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH,
		      "Muzzled users may not join chat rooms.");
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
	    return;		/* out of memory */
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
	log ("join(): user %s is already on channel %s", user->nick, chan->name);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH,
		      "You are already a member of channel %s", chan->name);
	return;
    }
	/* check to make sure the user has privilege to join */
    else if (user->level < chan->level)
    {
	log ("join(): channel %s is set to level %s", chan->name,
		Levels[chan->level]);
	if (ISUSER (con))
	    permission_denied (con);
	return;
    }

    ASSERT (validate_channel (chan));

    /* add this channel to the list of this user is subscribed to */
    list = CALLOC (1, sizeof (LIST));
    if (!list)
    {
	OUTOFMEMORY ("join");
	goto error;
    }
    list->data = chan;
    user->channels = list_append (user->channels, list);

    /* add this user to the channel members list */
    list = CALLOC (1, sizeof (LIST));
    if (!list)
    {
	OUTOFMEMORY ("join");
	goto error;
    }
    list->data = user;
    chan->users = list_append (chan->users, list);

    /* if there are linked servers, send this message along */
    pass_message_args (con, tag, ":%s %s", user->nick, chan->name);

    /* if local user send an ack for the join */
    if (ISUSER (con))
    {
	/* notify client of success */
	send_cmd (con, MSG_SERVER_JOIN_ACK, "%s", chan->name);

	/* send the client the list of current users in the channel */
	for (list = chan->users; list; list = list->next)
	{
	    chanUser = list->data;
	    ASSERT (chanUser != 0);
	    /* don't send info for the user that joined the channel */
	    if (chanUser != user)
	    {
		send_cmd (con, MSG_SERVER_CHANNEL_USER_LIST, "%s %s %d %d",
			  chan->name, chanUser->nick, chanUser->shared,
			  chanUser->speed);
	    }
	}
    }

    /* notify members of the channel that this user has joined.  note that
       we explicity send a 406 command to the user that just joined */
    for (list = chan->users; list; list = list->next)
    {
	chanUser = list->data;
	ASSERT (chanUser != 0);
	if (ISUSER (chanUser->con))
	    send_cmd (chanUser->con, MSG_SERVER_JOIN, "%s %s %d %d",
		      chan->name, user->nick, user->shared, user->speed);
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
    return;

  error:
    /* set things back to a sane state */
    chan->users = list_delete (chan->users, user);
    user->channels = list_delete (user->channels, chan);
    if (chan->users == 0)
    {
	log ("join(): destroying channel %s", chan->name);
	hash_remove (Channels, chan->name);
    }
}

/* ??? [ :<sender> ] <channel> <level>
   sets the minimum user level required to enter a channel */
HANDLER (channel_level)
{
    int level;
    char *sender;
    int ac;
    char *av[2];
    CHANNEL *chan;

    ASSERT (validate_connection (con));
    if (ISSERVER (con))
    {
	if (*pkt != ':')
	{
	    log ("channel_level(): missing sender name");
	    return;
	}
	pkt++;
	sender = next_arg (&pkt);
    }
    else
	sender = con->user->nick;
    ac = split_line (av, sizeof (av) / sizeof (char), pkt);
    if (ac != 2)
    {
	log ("channel_level(): wrong number of paramenters");
	print_args (ac, av);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "Invalid number of parameters");
	return;
    }
    level = get_level (av[1]);
    if (level == -1)
    {
	log ("channel_level(): unknown level %s", av[1]);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "Invalid level %s", av[1]);
	return;
    }
    if (ISUSER (con) && level > con->user->level)
    {
	log ("channel_level(): %s no privilege for channel %s to level %s",
		con->user->nick, Levels[level]);
	permission_denied (con);
	return;
    }
    chan = hash_lookup (Channels, av[0]);
    if (!chan)
    {
	log ("channel_level(): unable to find channel %s", av[0]);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "No such channel %s", av[0]);
	return;
    }
	/* ensure the user is a member of this channel */
    if (ISUSER (con) && list_find (con->user->channels, chan) == 0)
    {
	log ("channel_level(): %s is not a member of channel %s",
		sender, chan->name);
	send_cmd (con, MSG_SERVER_NOSUCH,
		"You are not a member of channel %s", chan->name);
	return;
    }

    pass_message_args (con, tag, ":%s %s %s", sender, chan->name,
	    Levels[level]);

    chan->level = level;

    notify_mods ("%s set channel %s to level %s.", sender, chan->name,
	    Levels[level]);
}
