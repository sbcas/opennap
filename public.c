/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdio.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <string.h>
#include "opennap.h"
#include "debug.h"

/* user sent a public message to a channel */
/* server sends: <channel> <nick> <text> */
/* client sends: <channel> <text> */
HANDLER (public)
{
    CHANNEL *chan;
    USER *user, *chanUser;
    LIST *list;
    int l, remote = 0;
    char *ptr;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    /* can't use split line here because the text field is considered all
       one item */

    /* extract the channel name. NOTE: we don't use next_arg() here because
       it will strip leading space from the text being sent */
    ptr = pkt;
    pkt = strchr (pkt, ' ');
    if (!pkt)
    {
	log ("public(): too few fields");
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "too few parameters for command");
	return;
    }
    *pkt++ = 0;

    /* find the channel this message is going to */
    chan = hash_lookup (Channels, ptr);
    if (!chan)
    {
	if (ISUSER (con))
	{
	    /* channel does not exist */
	    send_cmd (con, MSG_SERVER_NOSUCH, "Channel %s does not exist.",
		      ptr);
	}
	else
	    log ("public(): server sent message to nonexistent channel %s",
		ptr);
	return;
    }
    ASSERT (validate_channel (chan));

    if (ISSERVER (con))
    {
	/* find the USER struct for the sender */
	/* extract the channel name. NOTE: we don't use next_arg() here because
	   it will strip leading space from the text being sent */
	ptr = pkt;
	pkt = strchr (pkt, ' ');
	if (!pkt)
	{
	    log ("public(): server message has too few fields");
	    return;
	}
	*pkt++ = 0;
	user = hash_lookup (Users, ptr);
	if (!user)
	{
	    log ("public(): could not find user %s", ptr);
	    return;
	}
    }
    else
	user = con->user;

    ASSERT (validate_user (user));

    /* make sure this user is a member of the channel */
    list = list_find (user->channels, chan);
    if (!list)
    {
	/* user is not a member of this channel */
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH,
		"you are not on channel %s", chan->name);
	else
	    log ("public(): %s is not a member of channel %s", user->nick,
		chan->name);
	return;
    }

    if (user->muzzled)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "You are muzzled.");
	return;
    }

    /* format the message */
    snprintf (Buf + 4, sizeof (Buf) - 4, "%s %s %s", chan->name, user->nick,
	      pkt);
    l = strlen (Buf + 4);
    set_len (Buf, l);
    set_tag (Buf, MSG_SERVER_PUBLIC);

    /* send this message to everyone in the channel */
    for (list = chan->users; list; list = list->next)
    {
	chanUser = list->data;
	if (chanUser->local)
	    queue_data (chanUser->con, Buf, 4 + l);
	else
	    remote++;
    }

    /* if a local user, pass this message to our peer servers */
    /* this is an optimization for the case where all the users on a given
       channel are local.  we don't send the message to our peer servers if
       we detect this case */
    if (con->class == CLASS_USER && remote)
	pass_message (con, Buf, 4 + l);
}

/* 824 [ :<user> ] <channel> "<text>" */
HANDLER (emote)
{
    USER *user, *chanUser;
    CHANNEL *chan;
    int buflen, remote = 0;
    char *av[2];
    LIST *list;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &user) != 0)
	return;

    if (split_line (av, sizeof (av) / sizeof (char *), pkt) != 2)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_ERROR, "Wrong number of parameters for command.");
	return;
    }

    /* make sure this user is on the channel they are sending to */
    chan = hash_lookup (Channels, av[0]);
    if (!chan)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "No such channel %s", av[0]);
	return;
    }
    if (list_find (chan->users, user) == 0)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH,
		"You are not a member of channel %s", chan->name);
	return;
    }

    /* since we send the same data to multiple clients, format the data once
       and queue it up directly */
    set_tag (Buf, MSG_CLIENT_EMOTE);
    snprintf (Buf + 4, sizeof (Buf) - 4, "%s %s \"%s\"",
	    chan->name, user->nick, av[1]);
    buflen = strlen (Buf + 4);
    set_len (Buf, buflen);
    buflen += 4;

    /* send this message to all channel members */
    for (list = chan->users; list; list = list->next)
    {
	chanUser = list->data;
	if (chanUser->local)
	    queue_data (chanUser->con, Buf, buflen);
	else
	    remote++; /* we have to send this to other servers */
    }

    /* pass message to peer servers */
    if (ISUSER (con) && Num_Servers && remote)
	pass_message_args (con, MSG_CLIENT_EMOTE, ":%s %s \"%s\"",
		user->nick, chan->name, av[1]);
}
