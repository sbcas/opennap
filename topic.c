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
/* [ :<nick> ] <channel> [topic] */

HANDLER (topic)
{
    CHANNEL *chan;
    int l;
    char *chanName, *nick, *ptr;
    LIST *list;
    CHANUSER *chanUser;

    (void) len;
    ASSERT (validate_connection (con));

    /* don't use pop_user() because the server can set a channel topic */
    if (ISSERVER (con))
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
	nosuchchannel(con);
	return;
    }

    if (pkt)
    {
	/* check for permission to change the topic */
	if (ISUSER(con))
	{
	    if(con->user->level < chan->level)
	    {
		permission_denied(con);
		return;
	    }
	    if(con->user->level < LEVEL_MODERATOR)
	    {
		if(!list_find(con->user->channels,chan))
		{
		    send_cmd(con,MSG_SERVER_NOSUCH,
			    "topic change failed: you are not on channel %s",
			    chan->name);
		    return;
		}
		if(!(chan->flags & ON_CHANNEL_TOPIC) && !is_chanop(chan,con->user))
		{
		    send_cmd(con,MSG_SERVER_NOSUCH,
			    "topic change failed: permission denied");
		    return;
		}
	    }
	}

	if (chan->topic)
	    FREE (chan->topic);
	/* if the topic is too long, truncate it */
	if(Max_Topic > 0 && strlen(pkt) > (unsigned)Max_Topic)
	    *(pkt+Max_Topic)=0;
	if (!(chan->topic = STRDUP (pkt)))
	{
	    OUTOFMEMORY ("topic");
	    return;
	}
	/* make sure we don't have any wacky characters in the topic */
	for (ptr = chan->topic; *ptr; ptr++)
	    if (*ptr == '\r' || *ptr == '\n')
		*ptr = ' ';
	/* relay to peer servers */
	pass_message_args (con, tag, ":%s %s %s", nick, chan->name,
			   chan->topic);

	l = form_message (Buf, sizeof (Buf), tag, "%s %s", chan->name,
			  chan->topic);
	for (list = chan->users; list; list = list->next)
	{
	    chanUser = list->data;
	    ASSERT (chanUser->magic == MAGIC_CHANUSER);
	    if (chanUser->user->local)
		queue_data (chanUser->user->con, Buf, l);
	}
	notify_mods (TOPICLOG_MODE, "%s set topic on %s: %s", nick,
		     chan->name, chan->topic);
	notify_ops (chan, "%s set topic on %s: %s", nick,
		    chan->name, chan->topic);
    }
    else if (ISUSER (con))
    {
	/* return the current topic */
	send_cmd (con, tag, "%s %s", chan->name, chan->topic);
    }
}
