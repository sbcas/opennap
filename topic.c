/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.

   $Id$ */

#include <unistd.h>
#include <string.h>
#include "opennap.h"
#include "debug.h"

/* topic for channel has changed */
/* [ :<nick> ] <channel> <topic> */

HANDLER (topic)
{
    CHANNEL *chan;
    int i, l;
    char *topic;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    /* don't use pop_user() because the server can set a channel topic */
    if (con->class == CLASS_SERVER)
    {
	pkt = strchr (pkt, ' ');
	if (!pkt)
	{
	    log("topic(): too few fields in server message");
	    return;
	}
	pkt++;
    }
    else
    {
	ASSERT (con->class == CLASS_USER);

	ASSERT (validate_user (con->user));

	/* check to make sure this user has privilege to change topic */
	if (con->user->level < LEVEL_MODERATOR)
	{
	    log ("topic(): %s has no privilege", con->user->nick);
	    return;
	}
    }

    /* don't use split line because the topic could be multi-word */
    topic = strchr (pkt, ' ');
    if (!topic)
    {
	log ("topic(): malformed request");
	return;
    }
    *topic++ = 0;

    if (con->class == CLASS_USER)
    {
	/* find the channel in the user's list */
	for (i = 0; i < con->user->numchannels; i++)
	{
	    if (!strcasecmp (pkt, con->user->channels[i]->name))
		break;
	}
	if (i == con->user->numchannels)
	{
	    /* this user is not on the specified channel */
	    log ("topic(): user %s tried to change topic for %s",
		 con->user->nick, pkt);
	    return;
	}
	chan = con->user->channels[i];
    }
    else
    {
	/* server set the topic, probably after a netjoin */
	ASSERT (con->class == CLASS_SERVER);
	chan = hash_lookup (Channels, pkt);
    }

    ASSERT (validate_channel (chan));
    if (chan->topic)
	FREE (chan->topic);
    chan->topic = STRDUP (topic);

    /* if local user, notify our peers of this change */
    if (Num_Servers && con->class == CLASS_USER)
    {
	pass_message_args (con, MSG_SERVER_TOPIC, ":%s %s %s",
		con->user->nick, chan->name, topic);
    }

    /* notify the rest of the channel of the topic change. there should
       probably be another message type which contains the nick who changed
       the topic. */
    set_tag (Buf, MSG_SERVER_TOPIC);
    snprintf (Buf + 4, sizeof (Buf) - 4, "%s %s", chan->name, topic);
    l = strlen (Buf + 4);
    set_len (Buf, l);
    l += 4;

    for (i = 0; i < chan->numusers; i++)
    {
	if (chan->users[i]->con)
	    queue_data (chan->users[i]->con, Buf, l);
    }
}
