/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include "opennap.h"
#include "debug.h"

void
free_ban (BAN * b)
{
    if (b)
    {
	if (b->target)
	    FREE (b->target);
	if (b->setby)
	    FREE (b->setby);
	if (b->reason)
	    FREE (b->reason);
	FREE (b);
    }
}

/* 612 [ :<sender> ] <user|ip> [ "<reason>" ] */
HANDLER (ban)
{
    BAN *b;
    LIST *list;
    int ac = -1;
    char *av[2], *sender;

    (void) len;
    ASSERT (validate_connection (con));
    /* servers have to sync bans, so we don't authenticate the sender,
       we assume the other servers do their job */
    if (ISSERVER (con))
    {
	if (*pkt != ':')
	{
	    log ("ban(): missing sender name for server message");
	    return;
	}
	pkt++;
	sender = next_arg (&pkt);
    }
    else
    {
	/* make sure this user has privilege */
	if (con->user->level < LEVEL_MODERATOR)
	{
	    permission_denied (con);
	    return;
	}
	sender = con->user->nick;
    }
    if (pkt)
	ac = split_line (av, FIELDS (av), pkt);
    if (ac < 1)
    {
	unparsable (con);
	return;
    }
    /* check to see if this user is already banned */
    for (list = Bans; list; list = list->next)
    {
	b = list->data;
	if (!strcasecmp (av[0], b->target))
	{
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH, "already banned");
	    return;
	}
    }
    if (!is_ip (av[0]) && invalid_nick (av[0]))
    {
	invalid_nick_msg (con);
	return;
    }
    if (ac > 1)
    {
	truncate_reason (av[1]);
	pass_message_args (con, tag, ":%s %s \"%s\"", sender, av[0], av[1]);
    }
    else
	pass_message_args (con, tag, ":%s %s", sender, av[0]);

    do
    {
	/* create structure and add to global ban list */
	if (!(b = CALLOC (1, sizeof (BAN))))
	    break;
	if (!(b->target = STRDUP (av[0])))
	    break;
	if (!(b->setby = STRDUP (sender)))
	    break;
	if (!(b->reason = STRDUP (ac > 1 ? av[1] : "")))
	    break;
	b->when = Current_Time;
	/* determine if this ban is on an ip or a user */
	b->type = (is_ip (av[0])) ? BAN_IP : BAN_USER;
	list = CALLOC (1, sizeof (LIST));
	if (!list)
	    break;
	list->data = b;
	list->next = Bans;
	Bans = list;
	notify_mods (BANLOG_MODE, "%s banned %s: %s", sender, b->target,
		     b->reason);
	return;
    }
    while (1);

    /* we only get here on error */
    OUTOFMEMORY ("ban");
    free_ban (b);
    if (list)
	FREE (list);
}

/* 614 [ :<sender> ] <nick|ip> [ "<reason>" ] */
HANDLER (unban)
{
    USER *user;
    LIST **list, *tmpList;
    BAN *b;
    int ac = -1;
    char *av[2];

    (void) tag;
    (void) len;

    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &user) != 0)
	return;
    if (pkt)
	ac = split_line (av, FIELDS (av), pkt);
    if (ac < 1)
    {
	unparsable (con);
	return;
    }
    if (user->level < LEVEL_MODERATOR)
    {
	if (ISUSER (con))
	    permission_denied (con);
	return;
    }
    if (ac > 1)
	truncate_reason (av[1]);
    for (list = &Bans; *list; list = &(*list)->next)
    {
	b = (*list)->data;
	if (!strcasecmp (av[0], b->target))
	{
	    tmpList = *list;
	    *list = (*list)->next;
	    FREE (tmpList);
	    notify_mods (BANLOG_MODE, "%s removed ban on %s: %s",
			 user->nick, b->target, ac > 1 ? av[1] : "");
	    if (ac > 1)
		pass_message_args (con, tag, ":%s %s \"%s\"", user->nick,
				   b->target, av[1]);
	    else
		pass_message_args (con, tag, ":%s %s", user->nick, b->target);
	    free_ban (b);
	    return;
	}
    }
    if (ISUSER (con))
	send_cmd (con, MSG_SERVER_NOSUCH, "no such ban");
}

/* 615 */
/* show the list of current bans on the server */
HANDLER (banlist)
{
    LIST *list;
    BAN *ban;

    (void) tag;
    (void) len;
    (void) pkt;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("banlist");
    for (list = Bans; list; list = list->next)
    {
	ban = list->data;
	send_cmd (con, MSG_SERVER_IP_BANLIST /* 616 */ ,
		  "%s %s \"%s\" %ld 0", ban->target, ban->setby,
		  ban->reason, ban->when);
    }
#if 0
    /* the following doesnt seem to work with the windows client.  not sure
       that this is correct at all */
    for (list = Bans; list; list = list->next)
    {
	ban = list->data;
	if (ban->type == BAN_USER)
	    send_cmd (con, MSG_SERVER_NICK_BANLIST /* 626 */ , "%s",
		      ban->target);
    }
#endif
    /* terminate the banlist */
    send_cmd (con, MSG_CLIENT_BANLIST /* 615 */ , "");
}

int
check_ban (CONNECTION * con, const char *nick)
{
    LIST *list;
    BAN *ban;

    for (list = Bans; list; list = list->next)
    {
	ban = list->data;
	if ((ban->type == BAN_IP && ISUNKNOWN (con)
		    && ip_glob_match (ban->target, con->host))
		|| (ban->type == BAN_USER && !strcasecmp (ban->target, nick)))
	{
	    notify_mods (BANLOG_MODE,
		    "Connection from %s (%s): %s banned: %s",
		    nick, ISUNKNOWN(con) ? con->host : "remote",
		    ban->target, NONULL (ban->reason));
	    if (ISUNKNOWN (con))
	    {
		send_cmd (con, MSG_SERVER_ERROR,
			"%s banned: %s", ban->target, NONULL (ban->reason));
		con->destroy = 1;
		/* pass message along so all server mods+ see it.  only do
		   this for local users since the KILL message will serve
		   as notice otherwise */
		pass_message_args (NULL, MSG_SERVER_NOTIFY_MODS,
			":%s %d \"Connection from %s (%s): %s banned: %s\"",
			Server_Name, BANLOG_MODE, nick, con->host,
			ban->target, NONULL (ban->reason));
	    }
	    else if (ISSERVER (con) && ban->type == BAN_USER)
	    {
		/* issue a kill to remove this banned user */
		pass_message_args (con, MSG_CLIENT_KILL,
			":%s %s %s banned: %s", Server_Name, nick,
			ban->target, NONULL (ban->reason));
		notify_mods(KILLLOG_MODE,"%s killed %s: %s banned: %s",
			Server_Name, nick, ban->target, NONULL(ban->reason));
	    }
	    return 1;
	}
    }
    return 0;
}

int
save_bans (void)
{
    FILE *fp;
    LIST *list;
    BAN *b;
    char path[_POSIX_PATH_MAX];

    snprintf (path, sizeof (path), "%s/bans", Config_Dir);
    if ((fp = fopen (path, "w")) == 0)
    {
	logerr ("save_bans", path);
	return -1;
    }
    for (list = Bans; list; list = list->next)
    {
	b = list->data;
	fprintf (fp, "%s %s %d \"%s\"", b->target, b->setby,
		(int) b->when, b->reason);
#ifdef WIN32
	fputc ('\r', fp);
#endif
	fputc ('\n', fp);
    }
    if (fclose (fp))
    {
	logerr ("save_bans", "fclose");
	return -1;
    }
    return 0;
}

int
load_bans (void)
{
    FILE *fp;
    LIST *list, **last = &Bans;
    BAN *b;
    int ac;
    char *av[4], path[_POSIX_PATH_MAX];

    snprintf (path, sizeof (path), "%s/bans", Config_Dir);
    if (!(fp = fopen (path, "r")))
    {
	if (errno != ENOENT)
	    logerr ("load_bans", path);
	return -1;
    }
    while (fgets (Buf, sizeof (Buf) - 1, fp))
    {
	ac = split_line (av, FIELDS (av), Buf);
	if(ac<1)
	    continue;
	b = CALLOC (1, sizeof (BAN));
	if (!b)
	{
	    OUTOFMEMORY ("load_bans");
	    fclose (fp);
	    return -1;
	}
	b->type = (is_ip(av[0])) ? BAN_IP : BAN_USER;
	if(b->type==BAN_USER && invalid_nick(av[0]))
	{
	    log("load_bans(): invalid nick: %s", av[0]);
	    FREE(b);
	    continue;
	}
	b->target = STRDUP (av[0]);
	if (ac >= 4)
	{
	    b->setby = STRDUP (av[1]);
	    b->when = atol (av[2]);
	    truncate_reason (av[3]);
	    b->reason = STRDUP (av[3]);
	}
	else
	{
	    /* old user ban style */
	    b->setby = STRDUP (Server_Name);
	    b->reason = STRDUP ("");
	    b->when = Current_Time;
	}
	list = CALLOC (1, sizeof (LIST));
	if (!list)
	{
	    OUTOFMEMORY ("load_bans");
	    free_ban (b);
	    fclose (fp);
	    return -1;
	}
	list->data = b;
	/* keep the bans in the same order (roughly reverse chronological) */
	*last = list;
	last = &list->next;
    }
    fclose (fp);
    return 0;
}
