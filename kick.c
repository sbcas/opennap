/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"
#include "debug.h"

/* 10202 [ :<sender> ] <channel> <user> [ <reason> ] */
HANDLER (kick)
{
    char *nick, *chanName;
    USER *user, *sender;
    CHANNEL *chan;

    ASSERT (validate_connection (con));
    (void) len;
    if (pop_user (con, &pkt, &sender))
	return;
    chanName = next_arg (&pkt);
    nick = next_arg (&pkt);
    if (!chanName || !nick)
    {
	log ("kick(): too few parameters");
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "parameters are unparsable");
	return;
    }
    chan = hash_lookup (Channels, chanName);
    if (!chan)
    {
	log ("kick(): no such channel %s", chanName);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "No such channel");
	return;
    }
    if (list_find (sender->channels, chan) == 0)
    {
	log ("kick(): %s is not on channel %s", sender->nick, chan->name);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "You are not on that channel");
	return;
    }
    user = hash_lookup (Users, nick);
    if (!user)
    {
	log ("kick(): no such user %s", nick);
	if (ISUSER (con))
	    nosuchuser (con, nick);
	return;
    }
    if (sender->level < LEVEL_ELITE && sender->level <= user->level)
    {
	log ("kick(): %s has no privilege to kick %s", sender->nick,
	     user->nick);
	if (ISUSER (con))
	    permission_denied (con);
	return;
    }
    if (list_find (user->channels, chan) == 0)
    {
	log ("kick(): %s is not on channel %s", user->nick, chan->name);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "%s is not on that channel",
		      user->nick);
	return;
    }

    pass_message_args (con, tag, ":%s %s %s %s", sender->nick, chan->name,
		       user->nick, NONULL (pkt));
    if (ISUSER (user->con))
    {
	send_cmd (user->con, MSG_CLIENT_PART, chan->name);
	send_cmd (user->con, MSG_SERVER_NOSUCH,
		  "You were kicked from channel %s by %s: %s",
		  chan->name, sender->nick, NONULL (pkt));
    }

    user->channels = list_delete (user->channels, chan);

    part_channel (chan, user);

    notify_mods ("%s kicked %s out of channel %s: %s", sender->nick,
		 user->nick, chan->name, NONULL (pkt));
}
