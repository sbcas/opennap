/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"
#include "debug.h"

/* 10202 [ :<sender> ] <channel> <user> [ "<reason>" ] */
HANDLER (kick)
{
    char *av[3];
    int ac;
    USER *user, *sender;
    CHANNEL *chan;

    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &sender))
	return;
    ac = split_line (av, FIELDS (av), pkt);
    if (ac < 2)
    {
	log ("kick(): too few parameters");
	if (ISUSER (con))
	    unparsable (con);
	return;
    }
    chan = hash_lookup (Channels, av[0]);
    if (!chan)
    {
	log ("kick(): no such channel %s", av[0]);
	if (ISUSER (con))
	    nosuchchannel (con);
	return;
    }
    if (list_find (sender->channels, chan) == 0)
    {
	log ("kick(): %s is not on channel %s", sender->nick, chan->name);
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "You are not on that channel");
	return;
    }
    user = hash_lookup (Users, av[1]);
    if (!user)
    {
	log ("kick(): no such user %s", av[1]);
	if (ISUSER (con))
	    nosuchuser (con, av[1]);
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

    if (ac == 3)
	pass_message_args (con, tag, ":%s %s %s \"%s\"", sender->nick,
			   chan->name, user->nick, av[2]);
    else
	pass_message_args (con, tag, ":%s %s %s", sender->nick, chan->name,
			   user->nick);

    if (ISUSER (user->con))
    {
	send_cmd (user->con, MSG_CLIENT_PART, chan->name);
	send_cmd (user->con, MSG_SERVER_NOSUCH,
		  "You were kicked from channel %s%s%s: %s",
		  chan->name,
		  sender->cloaked?"":" by ",
		  sender->cloaked?"": sender->nick,
		  ac == 3 ? av[2] : "");
    }

    user->channels = list_delete (user->channels, chan);

    part_channel (chan, user);

    notify_mods (CHANNELLOG_MODE, "%s kicked %s out of channel %s: %s",
	    sender->nick, user->nick, chan->name, ac == 3 ? av[2] : "");
}

/* 820 [ :<sender> ] <channel> [ "<reason>" ] */
HANDLER (clear_channel)
{
    CHANNEL *chan;
    USER *sender, *user;
    LIST *list;
    int ac;
    char *av[2];

    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &sender))
	return;
    ac = split_line (av, FIELDS (av), pkt);
    if (ac < 1)
    {
	log ("clear_channel(): missing channel name");
	unparsable (con);
	return;
    }
    chan = hash_lookup (Channels, av[0]);
    if (!chan)
    {
	nosuchchannel (con);
	return;
    }
    if (sender->level < chan->level)
    {
	permission_denied (con);
	return;
    }
    if (ac == 1)
	pass_message_args (con, tag, ":%s %s", sender->nick, chan->name);
    else
	pass_message_args (con, tag, ":%s %s \"%s\"", sender->nick,
			   chan->name, av[1]);
    list = chan->users;
    while (list)
    {
	ASSERT (VALID_LEN (list, sizeof (LIST)));
	user = list->data;
	ASSERT (validate_user (user));
	/* part_channel() may free the current `list' pointer so we advance
	   it here prior to calling it */
	list = list->next;
	if (user != sender &&
	    (sender->level == LEVEL_ELITE || user->level < sender->level))
	{
	    user->channels = list_delete (user->channels, chan);
	    if (ISUSER (user->con))
	    {
		send_cmd (user->con, MSG_CLIENT_PART, "%s", chan->name);
		send_cmd (user->con, MSG_SERVER_NOSUCH,
			  "%s cleared channel %s: %s", sender->nick,
			  chan->name, ac > 1 ? av[1] : "");
	    }
	    part_channel (chan, user);
	}
    }
    notify_mods (CHANNELLOG_MODE, "%s cleared channel %s: %s", sender->nick,
	    chan->name, ac > 1 ? av[1] : "");
}
