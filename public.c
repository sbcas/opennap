/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "opennap.h"
#include "debug.h"

/* user sent a public message to a channel */
/* server sends: <channel> <nick> <text> */
/* client sends: <channel> <text> */
HANDLER (public)
{
    CHANNEL *chan;
    USER *user;
    int i, l, remote = 0;
    char *ptr;

    ASSERT (validate_connection (con));

    /* can't use split line here because the text field is considered all
       one item */

    /* extract the channel name */
    ptr = pkt;
    pkt = strchr (ptr, ' ');
    if (!pkt)
    {
	log ("public(): too few fields");
	return;
    }
    *pkt++ = 0;

    /* find the channel this message is going to */
    chan = hash_lookup (Channels, ptr);
    if (!chan)
    {
	if (con->class == CLASS_USER)
	{
	    /* channel does not exist */
	    send_cmd (con, MSG_SERVER_NOSUCH, "Channel %s does not exist!",
		      ptr);
	}
	else
	    log ("public(): server sent message to nonexistent channel %s",
		    ptr);
	return;
    }
    ASSERT (validate_channel (chan));

    if (con->class == CLASS_SERVER)
    {
	/* find the USER struct for the sender */
	ptr = pkt;
	pkt = strchr (ptr, ' ');
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
    for (i = 0; i < user->numchannels; i++)
	if (user->channels[i] == chan)
	    break;

    if (i == user->numchannels)
    {
	/* user is not a member of this channel */
	if (user->con)
	    send_cmd (user->con, MSG_SERVER_NOSUCH,
		"you are not on channel %s", chan->name);
	return;
    }

    if (user->muzzled)
    {
	if (user->con)
	    send_cmd (user->con, MSG_SERVER_NOSUCH, "You are muzzled.");
	return;
    }

    /* format the message */
    snprintf (Buf + 4, sizeof (Buf) - 4, "%s %s %s", chan->name, user->nick,
	      pkt);
    l = strlen (Buf + 4);
    set_len (Buf, l);
    set_tag (Buf, MSG_SERVER_PUBLIC);

    /* send this message to everyone in the channel */
    for (i = 0; i < chan->numusers; i++)
	if (chan->users[i]->con)
	    queue_data (chan->users[i]->con, Buf, 4 + l);
	else
	    remote++;

    /* if a local user, pass this message to our peer servers */
    /* this is an optimization for the case where all the users on a given
       channel are local.  we don't send the message to our peer servers if
       we detect this case */
    if (remote)
	pass_message (con, Buf, 4 + l);
}
