/* Copyright (C) 1999 drscholl@hotmail.com
   This is free software distributed under the terms of the
   GNU Public License. */

#include <unistd.h>
#include <string.h>
#include "opennap.h"
#include "debug.h"

/* topic for channel has changed */
/* [ :<nick> ] <channel> <topic> */

void
topic (CONNECTION * con, char *pkt)
{
    CHANNEL *chan;
    int i, l;
    char *fields[2];

    ASSERT (VALID (con));

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

	ASSERT (VALID (con->user));

	/* check to make sure this user has privilege to change topic */
	if ((con->user->flags & (FLAG_ADMIN | FLAG_MODERATOR)) == 0)
	{
	    log ("topic(): %s has no privilege", con->user->nick);
	    return;
	}
    }

    /* don't use split line because the topic could be multi-word */
    fields[0] = pkt;
    pkt = strchr (pkt, ' ');
    if (!pkt)
    {
	log ("topic(): malformed request");
	return;
    }
    *pkt = 0;
    fields[1] = pkt + 1;

    if (con->class == CLASS_USER)
    {
	/* find the channel in the user's list */
	for (i = 0; i < con->user->numchannels; i++)
	{
	    if (strcmp (fields[0], con->user->channels[i]->name) == 0)
		break;
	}
	if (i == con->user->numchannels)
	{
	    /* this user is not on the specified channel */
	    log ("topic(): user %s tried to change topic for %s",
		 con->user->nick, fields[0]);
	    return;
	}
	chan = con->user->channels[i];
    }
    else
    {
	/* server set the topic, probably after a netjoin */
	ASSERT (con->class == CLASS_SERVER);
	chan = hash_lookup (Channels, fields[0]);
    }

    ASSERT (VALID (chan));
    if (chan->topic)
	FREE (chan->topic);
    chan->topic = STRDUP (fields[1]);

    /* if local user, notify our peers of this change */
    if (Num_Servers && con->class == CLASS_USER)
    {
	pass_message_args (con, MSG_SERVER_TOPIC, ":%s %s %s",
		con->user->nick, chan->name, fields[1]);
    }

    /* notify the rest of the channel of the topic change. there should
       probably be another message type which contains the nick who changed
       the topic. */
    set_tag (Buf, MSG_SERVER_TOPIC);
    snprintf (Buf + 4, sizeof (Buf) - 4, "%s %s", chan->name, fields[1]);
    l = strlen (Buf + 4);
    set_len (Buf, l);
    l += 4;

    for (i = 0; i < chan->numusers; i++)
    {
	if (chan->users[i]->con)
	    queue_data (chan->users[i]->con, Buf, l);
    }
}
