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
#include <ctype.h>
#include "opennap.h"
#include "debug.h"

/* ensure the channel name contains only valid characters */
int
invalid_channel (const char *s)
{
    int count = 0;

    while (*s)
    {
	if (ISSPACE (*s) || !ISPRINT (*s) || *s == ':' || *s == '%')
	    return 1;
	count++;
	s++;
    }
    return ((count == 0));
}

static int
banned_from_channel (CHANNEL * chan, USER * user)
{
    LIST *list;
    BAN *b;

    strncpy (Buf, my_ntoa (user->host), sizeof (Buf));
    for (list = chan->bans; list; list = list->next)
    {
	b = list->data;
	if ((b->type == BAN_USER && !strcasecmp (user->nick, b->target)) ||
	    (b->type == BAN_IP && ip_glob_match (b->target, Buf)))
	{
	    log ("banned_from_channel(): %s is banned from %s: %s (%s)",
		 user->nick, chan->name, NONULL (b->reason), b->setby);
	    if (ISUSER (user->con))
	    {
		send_cmd (user->con, MSG_SERVER_NOSUCH,
			  "You are banned from %s: %s (%s)",
			  chan->name, NONULL (b->reason), b->setby);
	    }
	    return 1;
	}
    }
    return 0;
}

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
    if (!pkt || !*pkt)
    {
	unparsable(con);
	return;
    }
    /* enforce a maximum channels per user */
    /* TODO: if linked servers have different settings, the channel membership
       could become desynched */
    if (user->level < LEVEL_MODERATOR &&
	list_count (user->channels) > Max_User_Channels)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH,
		    "You may only join %d channels", Max_User_Channels);
	return;
    }
    if (user->muzzled)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH,
		      "Can't join channels while muzzled");
	return;
    }
    do
    {
	chan = hash_lookup (Channels, pkt);
	if (!chan)
	{
	    /* check if this server allows normals to create channels */
	    if (Server_Flags & OPTION_STRICT_CHANNELS)
	    {
		permission_denied (con);
		return;
	    }
	    if (invalid_channel (pkt))
	    {
		if (ISUSER (con))
		    send_cmd (con, MSG_SERVER_NOSUCH, "Invalid channel name");
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
	    chan->limit = Channel_Limit;	/* default */
	    chan->userCreated = 1;
	    chan->level = LEVEL_USER;
	    hash_add (Channels, chan->name, chan);
	    log ("join(): creating channel %s", chan->name);
	    break;
	}
	/* ensure that this user isn't already on this channel */
	else if (list_find (user->channels, chan))
	{
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH,
			"You have already joined that channel");
	    return;
	}
	/* check to make sure the user has privilege to join */
	else if (user->level < chan->level)
	{
	    permission_denied (con);
	    return;
	}
	/* check to make sure this user is not banned from the channel */
	else if (user->level < LEVEL_MODERATOR &&
		chan->bans && banned_from_channel (chan, user))
	{
	    /* log message is printed inside banned_from_channel() */
	    return;
	}
	else if (user->level < LEVEL_MODERATOR && chan->limit > 0 &&
		list_count (chan->users) >= chan->limit)
	{
	    log ("join(): channel %s is full (%d)", chan->name, chan->limit);
	    if (chan->userCreated)
	    {
		if (ISUSER (con))
		    send_cmd (con, MSG_SERVER_NOSUCH,
			    "channel join failed: channel is full");
		return;
	    }
	    /* for predefined channels, automatically create a rollover
	       channel when full */
	    else
	    {
		char *p;
		int n = 1;

		strncpy (Buf, chan->name, sizeof (Buf));
		p = Buf + strlen (Buf);
		while (p > Buf && isdigit (*(p - 1)))
		    p--;
		if (isdigit (*p))
		{
		    n = atoi (p);
		    *p = 0;
		}
		snprintf (Buf + strlen (Buf), sizeof (Buf) - strlen (Buf),
			  "%d", n);
		pkt = Buf;
		log ("join(): trying channel %s", pkt);
	    }
	}
	else
	    break;
    }
    while (1);

    ASSERT (validate_channel (chan));

    /* add this channel to the list of this user is subscribed to */
    list = MALLOC (sizeof (LIST));
    if (!list)
    {
	OUTOFMEMORY ("join");
	goto error;
    }
    list->data = chan;
    list->next = user->channels;
    user->channels = list;

    /* add this user to the channel members list */
    list = MALLOC (sizeof (LIST));
    if (!list)
    {
	OUTOFMEMORY ("join");
	goto error;
    }
    list->data = user;
    list->next = chan->users;
    chan->users = list;

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
	    if(!chanUser->cloaked || user->level >= LEVEL_MODERATOR)
		send_cmd (con, MSG_SERVER_CHANNEL_USER_LIST /* 408 */ ,
			"%s %s %d %d", chan->name, chanUser->nick,
			chanUser->shared, chanUser->speed);
	}
    }

    /* notify members of the channel that this user has joined */
    for (list = chan->users; list; list = list->next)
    {
	chanUser = list->data;
	ASSERT (chanUser != 0);
	if (ISUSER (chanUser->con) && chanUser != user &&
		(!user->cloaked || chanUser->level >= LEVEL_MODERATOR))
	    send_cmd (chanUser->con, MSG_SERVER_JOIN, "%s %s %d %d",
		    chan->name, user->nick, user->shared, user->speed);
    }

    if (ISUSER (con))
    {
	/* send end of channel list message */
	/* NOTE: for some reason this is the way the napster.com servers send
	   the messages.  I'm not sure why they send the end of channel list
	   AFTER the join message for yourself */
	send_cmd (con, MSG_SERVER_CHANNEL_USER_LIST_END /*409 */ , "%s",
		  chan->name);

	/* send channel topic */
	ASSERT (chan->topic != 0);
	send_cmd (con, MSG_SERVER_TOPIC /*410 */ , "%s %s", chan->name,
		  chan->topic);
    }
    return;

  error:
    /* set things back to a sane state */
    chan->users = list_delete (chan->users, user);
    user->channels = list_delete (user->channels, chan);
    if (!chan->users)
    {
	log ("join(): destroying channel %s", chan->name);
	hash_remove (Channels, chan->name);
    }
}

/* 10201 [ :<sender> ] <channel> [ <level> ]
   sets the minimum user level required to enter a channel */
HANDLER (channel_level)
{
    int level;
    char *sender;
    int ac;
    char *av[2];
    CHANNEL *chan;

    (void) len;
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
    if (ac == 0)
    {
	log ("channel_level(): wrong number of parameters");
	print_args (ac, av);
	unparsable (con);
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
    ASSERT (validate_channel);
    /* ensure the user is a member of this channel */
    if (ISUSER (con) && list_find (con->user->channels, chan) == 0)
    {
	send_cmd (con, MSG_SERVER_NOSUCH,
		  "You are not a member of that channel");
	return;
    }
    if (ac > 1)
    {
	level = get_level (av[1]);
	if (level == -1)
	{
	    log ("channel_level(): unknown level %s", av[1]);
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH, "invalid level %s", av[1]);
	    return;
	}
	if (ISUSER (con) && level > con->user->level)
	{
	    log ("channel_level(): %s no privilege for %s to %s",
		 con->user->nick, chan->name, Levels[level]);
	    permission_denied (con);
	    return;
	}
	pass_message_args (con, tag, ":%s %s %s", sender, chan->name,
			   Levels[level]);
	chan->level = level;
	notify_mods (CHANNELLOG_MODE, "%s set channel %s to level %s",
		     sender, chan->name, Levels[level]);
    }
    else
    {
	/* report the current level */
	ASSERT (ac == 1);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "Channel %s is set to level %s",
		      chan->name, Levels[chan->level]);
	else
	    log ("channel_level(): query from server (should not happen)");
    }
}

/* 826 [ :<sender> ] <channel> <limit> */
HANDLER (channel_limit)
{
    char *chanName, *sender;
    int limit;
    CHANNEL *chan;

    ASSERT (validate_connection (con));
    (void) len;
    if (ISSERVER (con))
    {
	if (*pkt != ':')
	{
	    log ("channel_limit(): malformed server command");
	    return;
	}
	pkt++;
	sender = next_arg (&pkt);
    }
    else
    {
	ASSERT (ISUSER (con));
	if (con->user->level < LEVEL_MODERATOR)
	{
	    permission_denied (con);
	    return;
	}
	sender = con->user->nick;
    }
    chanName = next_arg (&pkt);
    if (!chanName || !pkt)
    {
	unparsable (con);
	return;
    }
    limit = atoi (pkt);
    if (limit < 0 || limit > 65535)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "Invalid limit");
	return;
    }
    chan = hash_lookup (Channels, chanName);
    if (!chan)
    {
	if (ISUSER (con))
	    nosuchchannel (con);
	return;
    }
    if (ISUSER (con) && list_find (con->user->channels, chan) == 0)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "You are not on that channel");
	return;
    }
    chan->limit = limit;
    pass_message_args (con, tag, ":%s %s %d", sender, chan->name, limit);
    notify_mods (CHANNELLOG_MODE, "%s set limit on channel %s to %d",
		 sender, chan->name, limit);
}
