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

/* ensure the channel name contains only valid characters */
int
invalid_channel (const char *s)
{
    int count = 0;

    if(*s!='#'&&*s!='&')
	return 1;	/* must start with # or & */
    s++;
    while (*s)
    {
	if (*s < '!' || *s > '~' || strchr ("%$*?\",", *s))
	    return 1;
	count++;
	s++;
    }
    return ((count == 0)
	    || (Max_Channel_Length > 0 && count > Max_Channel_Length));
}

static BAN *
is_banned (LIST * bans, const char *nick, const char *host)
{
    char mask[256];

    snprintf (mask, sizeof (mask), "%s!%s", nick, host);
    for (; bans; bans = bans->next)
    {
	if (glob_match (((BAN *) bans->data)->target, mask))
	    return bans->data;
    }
    return 0;
}

/* handle client request to join channel */
/* [ :<nick> ] <channel> */
HANDLER (join)
{
    USER *user;
    CHANNEL *chan;
    LIST *list;
    CHANUSER *chanUser, *cu;
    int chanop = 0;
    char chanbuf[256];		/* needed when creating a rollover channel */

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &user) != 0)
	return;
    ASSERT (validate_user (user));
    if (!pkt || !*pkt)
    {
	unparsable (con);
	return;
    }

    if (user->level < LEVEL_MODERATOR)
    {
	/* enforce a maximum channels per user */
	/* TODO: if linked servers have different settings, the channel
	   membership could become desynched */
	if (list_count (user->channels) > Max_User_Channels)
	{
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH,
			  "channel join failed: you may only join %d channels",
			  Max_User_Channels);
	    return;
	}
	if (user->muzzled)
	{
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH,
			  "channel join failed: can't join channels while muzzled");
	    return;
	}
    }

    /* this loop is here in case the channel has a limit so we can create
       the rollover channels */
    ASSERT (sizeof (chanbuf) >= (unsigned int) Max_Channel_Length);
    chanbuf[sizeof (chanbuf) - 1] = 0;

    /* automatically prepend # to channel names if missing */
    if(*pkt!='#' && *pkt!='&')
    {
	snprintf(chanbuf,sizeof(chanbuf),"#%s",pkt);
	pkt=chanbuf;
    }

    for (;;)
    {
	chan = hash_lookup (Channels, pkt);
	if (!chan)
	{
	    /* check if this server allows normals to create channels */
	    if ((Server_Flags & ON_STRICT_CHANNELS) &&
		    user->level < LEVEL_MODERATOR)
	    {
		permission_denied (con);
		return;
	    }
	    if (invalid_channel (pkt))
	    {
		invalid_channel_msg (con);
		return;
	    }
	    chan = new_channel ();
	    if (!chan)
		return;		/* out of memory */
	    chan->name = STRDUP (pkt);
	    chan->timestamp = Current_Time;
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
	    chan->flags = ON_CHANNEL_USER;
	    chan->level = LEVEL_USER;
	    hash_add (Channels, chan->name, chan);
	    log ("join(): creating channel %s", chan->name);
	}
	/* ensure that this user isn't already on this channel */
	else if (list_find (user->channels, chan))
	{
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH,
			  "channel join failed: already joined channel");
	    return;
	}
	/* check to make sure the user has privilege to join */
	else if (user->level < chan->level)
	{
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH,
			  "channel join failed: requires level %s",
			  Levels[chan->level]);
	    return;
	}
	else
	{
	    /* check if this user is a channel operator */
	    for (list = chan->ops; list; list = list->next)
	    {
		if (!strcasecmp (user->nick, list->data))
		{
		    chanop = 1;
		    break;
		}
	    }

	    /* if not chanop or mod+, check extra permissions */
	    if (!chanop && user->level < LEVEL_MODERATOR)
	    {
		BAN *ban;

		/* check to make sure this user is not banned from the channel */
		if (
		    (ban =
		     is_banned (chan->bans, user->nick, my_ntoa (user->ip))))
		{
		    if (ISUSER (user->con))
		    {
			send_cmd (user->con, MSG_SERVER_NOSUCH,
				  "channel join failed: banned: %s",
				  NONULL (ban->reason));
		    }
		    return;
		}

		/* check for invitation */
		if ((chan->flags & ON_CHANNEL_INVITE) &&
		    !list_find (user->invited, chan))
		{
		    if (ISUSER (con))
			send_cmd (con, MSG_SERVER_NOSUCH,
				  "channel join failed: invite only");
		    return;
		}

		if (chan->limit > 0
		    && list_count (chan->users) >= chan->limit)
		{
		    if (chan->flags & ON_CHANNEL_USER)
		    {
			if (ISUSER (con))
			    send_cmd (con, MSG_SERVER_NOSUCH,
				      "channel join failed: channel full");
			return;
		    }
		    /* for predefined channels, automatically create a rollover
		       channel when full */
		    else
		    {
			char *p;
			int n = 1;

			if (pkt != chanbuf)
			{
			    strncpy (chanbuf, pkt, sizeof (chanbuf) - 1);
			    pkt = chanbuf;
			}
			p = chanbuf + strlen (chanbuf);
#define ISDIGIT(c) ((c)>=0 && (c)<='9')
			while (p > chanbuf && ISDIGIT (*(p - 1)))
			    p--;
			if (ISDIGIT (*p))
			{
			    n = atoi (p);
			    *p = 0;
			}
			snprintf (chanbuf + strlen (chanbuf),
				  sizeof (chanbuf) - strlen (Buf), "%d", n+1);
			log ("join(): trying channel %s", chanbuf);
			continue;
		    }
		}
	    }
	}
	break;
    }

    ASSERT (validate_channel (chan));

    /* clean up invite lists */
    if (chan->flags & ON_CHANNEL_INVITE)
    {
	chan->invited = list_delete (chan->invited, user);
	user->invited = list_delete (user->invited, chan);
    }

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
    chanUser = CALLOC (1, sizeof (CHANUSER));
#if DEBUG
    chanUser->magic = MAGIC_CHANUSER;
#endif
    chanUser->user = user;

    list = MALLOC (sizeof (LIST));
    if (!list)
    {
	OUTOFMEMORY ("join");
	goto error;
    }
    list->data = chanUser;
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
	    cu = list->data;
	    ASSERT (cu != 0);
	    ASSERT (cu->magic == MAGIC_CHANUSER);
	    if (!cu->user->cloaked || user->level >= LEVEL_MODERATOR)
		send_cmd (con, MSG_SERVER_CHANNEL_USER_LIST /* 408 */ ,
			  "%s %s %d %d", chan->name, cu->user->nick,
			  cu->user->shared, cu->user->speed);
	}
    }

    /* notify members of the channel that this user has joined */
    for (list = chan->users; list; list = list->next)
    {
	cu = list->data;
	ASSERT (cu != 0);
	ASSERT (cu->magic == MAGIC_CHANUSER);
	if (ISUSER (cu->user->con) && cu->user != user &&
	    (!user->cloaked || cu->user->level >= LEVEL_MODERATOR))
	    send_cmd (cu->user->con, MSG_SERVER_JOIN, "%s %s %d %d",
		      chan->name, user->nick, user->shared, user->speed);
    }

    /* notify ops/mods+ of this users status */
    if (chanop)
    {
	notify_ops (chan, "%s set %s as operator on channel %s",
		    Server_Name, user->nick, chan->name);
	chanUser->flags |= ON_OPERATOR;
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
	if (chanop)
	    send_cmd (con, MSG_SERVER_NOSUCH,
		      "%s set you as operator on channel %s",
		      Server_Name, chan->name);
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

/* 823 [ :<sender> ] <channel> [level] [timestamp]
   sets the minimum user level required to enter a channel */
HANDLER (channel_level)
{
    int level;
    char *sender;
    int ac;
    char *av[3];
    CHANNEL *chan;

    (void) tag;
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
	nosuchchannel (con);
	return;
    }
    ASSERT (validate_channel);
    if (ac > 1)
    {
	level = get_level (av[1]);
	if (level == -1)
	{
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH, "invalid level");
	    return;
	}
	if (chan->level == level)
	    return;		/* same value, ignore */
	/* check for permission */
	if (ISUSER (con) &&
	    (chan->level > con->user->level ||
	     level > con->user->level ||
	     (con->user->level < LEVEL_MODERATOR
	      && !is_chanop (chan, con->user))))
	{
	    permission_denied (con);
	    return;
	}
	/* check the TS if present */
	if (ISSERVER (con) && ac > 2)
	{
	    time_t ts = atoi (av[2]);

	    if (ts > chan->timestamp)
	    {
		log ("channel_level(): TS is newer, ignoring");
		return;
	    }
	}
	pass_message_args (con, MSG_CLIENT_SET_CHAN_LEVEL, ":%s %s %s",
		sender, chan->name,
			   Levels[level]);
	chan->level = level;
	notify_ops (chan, "%s set channel %s to level %s",
		    sender, chan->name, Levels[level]);
    }
    else
    {
	/* report the current level */
	ASSERT (ac == 1);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "channel %s is set to level %s",
		      chan->name, Levels[chan->level]);
	else
	    log ("channel_level(): query from server (should not happen)");
    }
}

/* 826 [ :<sender> ] <channel> <limit> [timestamp] */
HANDLER (channel_limit)
{
    char *chanName, *sender, *slimit;
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
	sender = con->user->nick;
    }
    chanName = next_arg (&pkt);
    slimit = next_arg (&pkt);
    if (!chanName || !slimit)
    {
	unparsable (con);
	return;
    }
    limit = atoi (slimit);
    if (limit < 0 || limit > 65535)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "invalid limit");
	return;
    }
    chan = hash_lookup (Channels, chanName);
    if (!chan)
    {
	nosuchchannel (con);
	return;
    }
    if (chan->limit == limit)
    {
	/* same value, just ignore it */
	return;
    }
    if (ISUSER (con))
    {
	if (con->user->level < LEVEL_MODERATOR
	    && !is_chanop (chan, con->user))
	{
	    permission_denied (con);
	    return;
	}
    }
    else
    {
	/* when synching servers, check the timestamp to handle differences */
	ASSERT (ISSERVER (con));
	if (pkt)
	{
	    time_t timestamp = atoi (pkt);

	    if (timestamp > chan->timestamp)
	    {
		log ("channel_limit(): newer timestamp, ignoring");
		return;
	    }
	    else if (timestamp == chan->timestamp)
	    {
		/* TODO: need to handle this case at some point */
		log
		    ("channel_limit(): WARNING: TS was equal, but different value");
	    }
	}
    }
    chan->limit = limit;
    chan->timestamp = Current_Time;
    pass_message_args (con, tag, ":%s %s %d", sender, chan->name, limit);
    notify_ops (chan, "%s set limit on channel %s to %d",
		sender, chan->name, limit);
}
