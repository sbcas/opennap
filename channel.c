/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

void
load_channels (void)
{
    char path[_POSIX_PATH_MAX], *av[4];
    FILE *fp;
    int ac, limit, level;
    CHANNEL *chan;

    snprintf (path, sizeof (path), "%s/channels", Config_Dir);
    fp = fopen (path, "r");
    if (!fp)
    {
	log ("load_channels(): %s: %s (errno %d)", path, strerror (errno),
	     errno);
	return;
    }
    while (fgets (Buf, sizeof (Buf), fp))
    {
	if (Buf[0] == '#' || Buf[0] == '\r' || Buf[0] == '\n')
	    continue;		/* blank or comment line */
	ac = split_line (av, FIELDS (av), Buf);
	if (ac < 3)
	{
	    log ("load_channels(): too few parameters for channel %s",
		 ac > 1 ? av[0] : "(unknown)");
	    continue;
	}
	level = get_level (av[2]);
	if (level == -1)
	{
	    log ("load_channels(): invalid level %s for channel %s",
		 av[2], av[0]);
	    continue;
	}
	limit = atoi (av[1]);
	if (limit < 0 || limit > 65535)
	{
	    log ("load_channels(): invalid limit %d for channel %s",
		 limit, av[0]);
	    continue;
	}
	chan = CALLOC (1, sizeof (CHANNEL));
	if (chan)
	{
#if DEBUG
	    chan->magic = MAGIC_CHANNEL;
#endif
	    chan->name = STRDUP (av[0]);
	    if (ac > 3)
		chan->topic = STRDUP (av[3]);
	    chan->limit = limit;
	    chan->level = level;
	}
	if (hash_add (Channels, chan->name, chan))
	    free_channel (chan);
    }
}

/* 10204 [ :<sender> ] <channel> <user|ip> [ "<reason>" ] */
HANDLER (channel_ban)
{
    CHANNEL *chan;
    char *av[3], *sender;
    int ac = -1;
    LIST *list;
    BAN *b;

    (void) len;
    ASSERT (validate_connection (con));
    if (ISSERVER (con))
    {
	if (*pkt != ':')
	{
	    log ("channel_ban(): missing sender");
	    return;
	}
	pkt++;
	sender = next_arg (&pkt);
    }
    else
    {
	if (con->user->level < LEVEL_MODERATOR)
	{
	    permission_denied (con);
	    return;
	}
	sender = con->user->nick;
    }
    if (pkt)
	ac = split_line (av, FIELDS (av), pkt);
    if (ac < 2)
    {
	unparsable (con);
	return;
    }
    chan = hash_lookup (Channels, av[0]);
    if (!chan)
    {
	log ("channel_ban(): no such channel %s", av[0]);
	nosuchchannel (con);
	return;
    }
    /* ensure this user/ip is not already banned */
    for (list = chan->bans; list; list = list->next)
    {
	b = list->data;
	if (!strcasecmp (b->target, av[1]))
	{
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH,
			  "%s is already banned from %s", b->target,
			  chan->name);
	    return;
	}
    }
    b = CALLOC (1, sizeof (BAN));
    if (b)
    {
	b->setby = STRDUP (sender);
	b->target = STRDUP (av[1]);
	b->type = is_ip (av[1]) ? BAN_IP : BAN_USER;
	b->when = Current_Time;
	if (ac > 2)
	    b->reason = STRDUP (av[2]);
    }
    if (!b || !b->setby || !b->target || (ac > 2 && !b->reason))
    {
	OUTOFMEMORY ("channel_ban");
	return;
    }
    list = CALLOC (1, sizeof (LIST));
    if (!list)
    {
	OUTOFMEMORY ("channel_ban");
	free_ban (b);
	return;
    }
    list->data = b;
    list->next = chan->bans;
    chan->bans = list;

    pass_message_args (con, tag, ":%s %s %s%s%s%s", sender, chan->name,
		       b->target, ac > 2 ? " \"" : "", ac > 2 ? av[2] : "",
		       ac > 2 ? "\"" : "");
    notify_mods (BANLOG_MODE, "%s banned %s from %s: %s", sender, b->target,
		 NONULL (b->reason));
}

/* 10205 [ :<sender> ] <channel> <user|ip> [ "<reason>" ] */
HANDLER (channel_unban)
{
    char *sender, *av[3];
    int ac = -1;
    LIST **list, *tmpList;
    BAN *b;
    CHANNEL *chan;

    (void) len;
    ASSERT (validate_connection (con));

    if (ISSERVER (con))
    {
	if (*pkt != ':')
	{
	    log ("channel_unban(): missing sender");
	    return;
	}
	pkt++;
	sender = next_arg (&pkt);
    }
    else
    {
	if (con->user->level < LEVEL_MODERATOR)
	{
	    permission_denied (con);
	    return;
	}
	sender = con->user->nick;
    }
    if (pkt)
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
    ASSERT (validate_channel (chan));
    for (list = &chan->bans; *list; list = &(*list)->next)
    {
	b = (*list)->data;
	if (!strcasecmp (av[1], b->target))
	{
	    pass_message_args (con, tag, ":%s %s %s%s%s%s",
			       sender, chan->name, b->target,
			       ac > 2 ? " \"" : "",
			       ac > 2 ? av[2] : "", ac > 2 ? "\"" : "");
	    notify_mods (BANLOG_MODE, "%s unbanned %s from %s: %s",
			 sender, b->target, (ac > 2) ? av[2] : "");
	    free_ban (b);
	    tmpList = *list;
	    *list = (*list)->next;
	    FREE (tmpList);
	    return;
	}
    }
    if (ISUSER (con))
	send_cmd (con, MSG_SERVER_NOSUCH, "No ban on %s for %s", av[0],
		  av[1]);
}

/* 10206 <channel> */
HANDLER (channel_banlist)
{
    CHANNEL *chan;
    LIST *list;
    BAN *b;

    (void) len;
    CHECK_USER_CLASS ("channel_banlist");
    chan = hash_lookup (Channels, pkt);
    if (!chan)
    {
	nosuchchannel (con);
	return;
    }
    for (list = chan->bans; list; list = list->next)
    {
	b = list->data;
	send_cmd (con, tag, "%s %s \"%s\" %d", b->target, b->setby,
		  NONULL (b->reason), (int) b->when);
    }
    send_cmd (con, tag, "");
}
