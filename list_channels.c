/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"
#include "debug.h"

static void
channel_info (void *elem, void *data)
{
    CHANNEL *chan = (CHANNEL *) elem;

    ASSERT (VALID (elem));
    ASSERT (VALID (data));
    send_cmd ((CONNECTION *) data, MSG_SERVER_CHANNEL_LIST /* 618 */ ,
	      "%s %d %s", chan->name, list_count (chan->users), chan->topic);
}

/* send a list of channels we know about to the user */
HANDLER (list_channels)
{
    ASSERT (validate_connection (con));

    (void) pkt;			/* unused */
    (void) tag;
    (void) len;

    CHECK_USER_CLASS ("list_channels");
    hash_foreach (Channels, channel_info, con);
    send_cmd (con, MSG_SERVER_CHANNEL_LIST_END /* 617 */ , "");
}

static void
full_channel_info (CHANNEL * chan, CONNECTION * con)
{
    ASSERT (validate_channel (chan));
    ASSERT (validate_connection (con));
    ASSERT (chan->topic != 0);
    send_cmd (con, MSG_SERVER_FULL_CHANNEL_INFO, "%s %d %d %d %d \"%s\"",
	      chan->name, list_count (chan->users), chan->userCreated,
	      chan->level, chan->limit, chan->topic);
}

/* 827 */
HANDLER (full_channel_list)
{
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("list_all_channels");
    (void) pkt;
    (void) len;
    hash_foreach (Channels, (hash_callback_t) full_channel_info, con);
    send_cmd (con, tag, "");
}
