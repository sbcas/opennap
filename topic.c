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
    if (ISSERVER(con))
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
    if(invalid_channel(chanName))
    {
	invalid_channel_msg(con);
	return;
    }
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
	if (ISUSER (con) && con->user->level < LEVEL_MODERATOR &&
	    !is_chanop(chan,con->user))
	{
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
	/* make sure we don't have any wacky characters in the topic */
	for(ptr=chan->topic;*ptr;ptr++)
	    if(*ptr=='\r' || *ptr=='\n')
		*ptr=' ';
	/* relay to peer servers */
	pass_message_args (con, tag, ":%s %s %s", nick, chan->name, chan->topic);

	l = form_message (Buf, sizeof (Buf), tag, "%s %s", chan->name, chan->topic);
	for (list = chan->users; list; list = list->next)
	{
	    chanUser=list->data;
	    ASSERT(chanUser->magic==MAGIC_CHANUSER);
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
    else
    {
	ASSERT (ISSERVER (con));
	log ("topic(): error, server %s requested topic", con->host);
    }
}
