/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"
#include "debug.h"

int
is_chanop (CHANNEL * chan, USER * user)
{
    LIST *list;
    CHANUSER *chanUser;

    for (list = chan->users; list; list = list->next)
    {
	chanUser = list->data;
	ASSERT (chanUser->magic == MAGIC_CHANUSER);
	if (chanUser->user == user)
	{
	    return (chanUser->flags & ON_OPERATOR);
	    break;
	}
    }
    return 0;
}

static int
can_kick (CHANNEL * chan, USER * sender, USER * user)
{
    if (sender->level == LEVEL_ELITE || sender->level > user->level ||
	(is_chanop (chan, sender) && sender->level == user->level))
	return 1;
    return 0;
}

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
	unparsable (con);
	return;
    }
    chan = hash_lookup (Channels, av[0]);
    if (!chan)
    {
	nosuchchannel (con);
	return;
    }
    if (list_find (sender->channels, chan) == 0)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "You are not on that channel");
	return;
    }
    user = hash_lookup (Users, av[1]);
    if (!user)
    {
	nosuchuser (con);
	return;
    }
    if (sender->level < chan->level || !can_kick (chan, sender, user))
    {
	permission_denied (con);
	return;
    }
    if (list_find (user->channels, chan) == 0)
    {
	/* OK to return the nick here since we checked for existence above.
	   I'm assuming that the user could not log in with an invalid nick */
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "users is not on that channel");
	return;
    }

    if (ac == 3)
    {
	truncate_reason(av[2]);
	pass_message_args (con, tag, ":%s %s %s \"%s\"", sender->nick,
			   chan->name, user->nick, av[2]);
    }
    else
	pass_message_args (con, tag, ":%s %s %s", sender->nick, chan->name,
			   user->nick);

    if (ISUSER (user->con))
    {
	send_cmd (user->con, MSG_CLIENT_PART, chan->name);
	send_cmd (user->con, MSG_SERVER_NOSUCH,
		  "You were kicked from channel %s%s%s: %s",
		  chan->name,
		  (sender->cloaked && user->level < LEVEL_MODERATOR) ? "" : " by ",
		  (sender->cloaked && user->level < LEVEL_MODERATOR) ? "" : sender->nick,
		  ac == 3 ? av[2] : "");
    }

    user->channels = list_delete (user->channels, chan);

    notify_mods (CHANNELLOG_MODE, "%s kicked %s out of channel %s: %s",
		 sender->nick, user->nick, chan->name, ac == 3 ? av[2] : "");
    notify_ops (chan, "%s kicked %s out of channel %s: %s",
		sender->nick, user->nick, chan->name, ac == 3 ? av[2] : "");

    /* has to come after the notify_mods() since it uses chan->name and
       chan may disappear if there are no users left
       Greg Prosser <greg@snickers.org> */
    part_channel (chan, user);
}

/* 820 [ :<sender> ] <channel> [reason] */
HANDLER (clear_channel)
{
    CHANNEL *chan;
    CHANUSER *chanUser;
    USER *sender;
    LIST *list;
    char *chanName;

    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &sender))
	return;
    chanName = next_arg (&pkt);
    if (!chanName)
    {
	unparsable (con);
	return;
    }
    chan = hash_lookup (Channels, chanName);
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
    if(pkt)
	truncate_reason(pkt);
    pass_message_args (con, tag, ":%s %s %s", sender->nick, chan->name,
	    NONULL (pkt));
    notify_mods (CHANNELLOG_MODE, "%s cleared channel %s: %s", sender->nick,
	    chan->name, NONULL (pkt));
    notify_ops (chan, "%s cleared channel %s: %s", sender->nick,
	    chan->name, NONULL (pkt));
    list = chan->users;
    while (list)
    {
	ASSERT (VALID_LEN (list, sizeof (LIST)));
	chanUser = list->data;
	ASSERT (chanUser->magic == MAGIC_CHANUSER);
	/* part_channel() may free the current `list' pointer so we advance
	   it here prior to calling it */
	list = list->next;
	if (chanUser->user != sender
		&& can_kick (chan, sender, chanUser->user))
	{
	    chanUser->user->channels =
		list_delete (chanUser->user->channels, chan);
	    if (ISUSER (chanUser->user->con))
	    {
		send_cmd (chanUser->user->con, MSG_CLIENT_PART, "%s",
			chan->name);
		send_cmd (chanUser->user->con, MSG_SERVER_NOSUCH,
			"%s cleared channel %s: %s", sender->nick,
			chan->name, NONULL (pkt));
	    }
	    part_channel (chan, chanUser->user);
	}
    }
}
