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
    if(!is_ip(av[0]) && invalid_nick(av[0]))
    {
	invalid_nick_msg(con);
	return;
    }
    if (ac > 1)
    {
	truncate_reason(av[1]);
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
	Bans = list_append (Bans, list);
	notify_mods (BANLOG_MODE, "%s banned %s: %s", sender, av[0],
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
    if(ac>1)
	truncate_reason(av[1]);
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
check_ban (CONNECTION * con, const char *target, ban_t type)
{
    LIST *list;
    BAN *ban;

    /* make sure this target is not banned */
    for (list = Bans; list; list = list->next)
    {
	ban = list->data;
	if (ban->type == type &&
	    ((type == BAN_IP && ip_glob_match (ban->target, target)) ||
	     (type == BAN_USER && !strcasecmp (ban->target, target))))
	{
	    log ("check_ban(): %s is banned: %s", ban->target,
		 NONULL (ban->reason));
	    if (ISUNKNOWN (con))
		send_cmd (con,
			  (type ==
			   BAN_IP) ? MSG_SERVER_ERROR : MSG_SERVER_NOSUCH,
			  "You are banned from this server: %s",
			  NONULL (ban->reason));
	    notify_mods (BANLOG_MODE,
			 "Connection from banned %s %s (%s): %s",
			 (type == BAN_IP) ? "host" : "user", target,
			 (type == BAN_IP) ? ban->target : my_ntoa (con->ip),
			 NONULL (ban->reason));
	    /* pass message along so all server mods+ see it */
	    pass_message_args (NULL, MSG_SERVER_NOTIFY_MODS,
			       ":%s %d \"Connection from banned %s %s (%s): %s\"",
			       Server_Name, BANLOG_MODE,
			       (type == BAN_IP) ? "host" : "user",
			       target,
			       (type ==
				BAN_IP) ? ban->target : my_ntoa (con->ip),
			       NONULL (ban->reason));
	    if (con->class == CLASS_UNKNOWN)
		con->destroy = 1;
	    else if (ISSERVER (con) && type == BAN_USER)
	    {
		/* issue a kill to remove this banned user */
		pass_message_args (con, MSG_CLIENT_BAN, ":%s %s banned user",
				   Server_Name, target);
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
	log ("save_bans(): %s: %s (errno %d)", path, strerror (errno), errno);
	return -1;
    }
    for (list = Bans; list; list = list->next)
    {
	b = list->data;
	if (b->type == BAN_IP)
	    fprintf (fp, "%s %s %d \"%s\"", b->target, b->setby,
		     (int) b->when, b->reason);
	else
	    fprintf (fp, "%s", b->target);
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
    LIST *list;
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
	b = CALLOC (1, sizeof (BAN));
	if (!b)
	{
	    OUTOFMEMORY ("load_bans");
	    fclose (fp);
	    return -1;
	}
	b->target = STRDUP (av[0]);
	if (is_ip (av[0]))
	{
	    if (ac >= 4)
	    {
		b->type = BAN_IP;
		b->setby = STRDUP (av[1]);
		b->when = atol (av[2]);
		truncate_reason(av[3]);
		b->reason = STRDUP (av[3]);
	    }
	    else
	    {
		log ("load_bans(): too few parameters for ban");
		print_args (ac, av);
	    }
	}
	else
	{
	    b->type = BAN_USER;
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
	list->next = Bans;
	Bans = list;
    }
    fclose (fp);
    return 0;
}
