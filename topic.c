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
/* [ :<nick> ] <channel> <topic> */

HANDLER (topic)
{
    CHANNEL *chan;
    int l;
    USER *chanUser;
    char *chanName, *nick;
    LIST *list;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    /* don't use pop_user() because the server can set a channel topic */
    if (con->class == CLASS_SERVER)
    {
	pkt++;
	nick=next_arg(&pkt);
	if (!pkt)
	{
	    log("topic(): too few fields in server message");
	    return;
	}
    }
    else
    {
	ASSERT (ISUSER (con));
	ASSERT (validate_user (con->user));

	/* check to make sure this user has privilege to change topic */
	if (con->user->level < LEVEL_MODERATOR)
	{
	    log ("topic(): %s has no privilege", con->user->nick);
	    return;
	}
	nick=con->user->nick;
    }

    /* don't use split line because the topic could be multi-word */
    chanName = next_arg (&pkt);
    if (!pkt)
    {
	log ("topic(): malformed request");
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
	send_cmd (con, MSG_SERVER_NOSUCH, "You are not a member of channel %s",
	    chanName);
	return;
    }

    if (chan->topic)
	FREE (chan->topic);
    if (!(chan->topic = STRDUP (pkt)))
    {
	OUTOFMEMORY ("topic");
	return;
    }

    if (Num_Servers)
	pass_message_args (con, MSG_SERVER_TOPIC, ":%s %s %s",
		nick, chan->name, chan->topic);

    /* notify the rest of the channel of the topic change. there should
       probably be another message type which contains the nick who changed
       the topic. */
    set_tag (Buf, MSG_SERVER_TOPIC);
    snprintf (Buf + 4, sizeof (Buf) - 4, "%s %s", chan->name, chan->topic);
    l = strlen (Buf + 4);
    set_len (Buf, l);
    l += 4;

    for (list = chan->users; list; list = list->next)
    {
	chanUser = list->data;
	if (chanUser->local)
	    queue_data (chanUser->con, Buf, l);
    }
}
