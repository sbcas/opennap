/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.

   $Id$ */

#ifndef WIN32
#include <unistd.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "opennap.h"
#include "debug.h"

/* topic for channel has changed */
/* [ :<nick> ] <channel> [ <topic> ] */

HANDLER (topic)
{
    CHANNEL *chan;
    int l;
    char *chanName, *nick;
    LIST *list;

    (void) len;
    ASSERT (validate_connection (con));

    /* don't use pop_user() because the server can set a channel topic */
    if (con->class == CLASS_SERVER)
    {
	pkt++;
	nick = next_arg (&pkt);
	if (!pkt)
	{
	    log ("topic(): too few fields in server message");
	    return;
	}
    }
    else
    {
	ASSERT (ISUSER (con));
	ASSERT (validate_user (con->user));
	nick = con->user->nick;
    }

    /* don't use split line because the topic could be multi-word */
    chanName = next_arg (&pkt);
    chan = hash_lookup (Channels, chanName);
    if (!chan)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "No such channel %s", chanName);
	return;
    }
    ASSERT (validate_channel (chan));
    if (ISUSER (con) && list_find (con->user->channels, chan) == 0)
    {
	send_cmd (con, MSG_SERVER_NOSUCH,
		  "You are not a member of channel %s", chanName);
	return;
    }

    if (pkt)
    {
	/* check to make sure this user has privilege to change topic */
	if (ISUSER (con) && con->user->level < LEVEL_MODERATOR)
	{
	    log ("topic(): %s has no privilege", con->user->nick);
	    permission_denied (con);
	    return;
	}
	if (chan->topic)
	    FREE (chan->topic);
	if (!(chan->topic = STRDUP (pkt)))
	{
	    OUTOFMEMORY ("topic");
	    return;
	}
	/* relay to peer servers */
	pass_message_args (con, tag, ":%s %s %s", nick, chan->name, chan->topic);

	l = form_message (Buf, sizeof (Buf), tag, "%s %s", chan->name, chan->topic);
	for (list = chan->users; list; list = list->next)
	{
#define chanUser ((USER*)list->data)
	    if (chanUser->local)
		queue_data (chanUser->con, Buf, l);
	}
    }
    else if (ISUSER (con))
    {
	/* return the current topic */
	send_cmd (con, tag, "%s %s", chan->name, chan->topic);
    }
    else
    {
	ASSERT (ISSERVER (con));
	log ("topic(): error, server %s requested topic", con->host);
    }
}
