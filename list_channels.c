/* Copyright (C) 2000 drscholl@hotmail.com
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include "opennap.h"
#include "debug.h"

static void
channel_info (void *elem, void *data)
{
    CHANNEL *chan = (CHANNEL *) elem;

    ASSERT (VALID (elem));
    ASSERT (VALID (data));
    send_cmd ((CONNECTION *) data, MSG_SERVER_CHANNEL_LIST /* 618 */,
	    "%s %d %s", chan->name, chan->numusers, chan->topic);
}

/* send a list of channels we know about to the user */
void
list_channels (CONNECTION *con, char *pkt)
{
    ASSERT (VALID (con));

    (void) pkt; /* unused */

    if (con->class != CLASS_USER)
    {
	log ("list_channels(): not USER class");
	return;
    }

    hash_foreach (Channels, channel_info, con);

    send_cmd (con, MSG_SERVER_CHANNEL_LIST_END /* 617 */, "");
}
