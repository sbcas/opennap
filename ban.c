/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "opennap.h"
#include "debug.h"

/* an ip address consists of only numbers and dots */
static int
is_ip (const char *s)
{
    for (; *s; s++)
	if (!isdigit ((unsigned char) *s) && *s != '.')
	    return 0;
    return 1;
}

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

/* 612 [ :<sender> ] <user|ip> [ <reason> ] */
HANDLER (ban)
{
    USER *sender;
    char *ban;
    BAN *b;
    LIST *list;

    (void) tag;
    (void) len;

    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &sender) != 0)
	return;

    /* make sure this user has privilege */
    ASSERT (validate_user (sender));
    if (sender->level < LEVEL_MODERATOR)
    {
	if (ISUSER (con))
	    permission_denied (con);
	return;
    }
    ban = next_arg (&pkt);
    /* check to see if this user is already banned */
    for (list = Bans; list; list = list->next)
    {
	b = list->data;
	if (!strcasecmp (ban, b->target))
	{
	    log ("ban(): %s is already banned", ban);
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH, "%s is already banned",
			  ban);
	    return;
	}
    }

    pass_message_args (con, tag, ":%s %s %s", sender->nick, ban,
		       NONULL (pkt));

    do
    {
	/* create structure and add to global ban list */
	if (!(b = CALLOC (1, sizeof (BAN))))
	    break;
	if (!(b->target = STRDUP (ban)))
	    break;
	if (!(b->setby = STRDUP (sender->nick)))
	    break;
	if (!(b->reason = STRDUP (NONULL (pkt))))
	    break;
	b->when = Current_Time;
	/* determine if this ban is on an ip or a user */
	b->type = (is_ip (ban)) ? BAN_IP : BAN_USER;
	list = CALLOC (1, sizeof (LIST));
	if (!list)
	    break;
	list->data = b;
	Bans = list_append (Bans, list);
	notify_mods ("%s banned %s: %s", sender->nick, ban, NONULL (pkt));
	return;
    }
    while (1);

    /* we only get here on error */
    OUTOFMEMORY ("ban");
    free_ban (b);
    if (list)
	FREE (list);
}

/* 614 [ :<sender> ] <nick|ip> */
HANDLER (unban)
{
    USER *user;
    LIST **list, *tmpList;
    BAN *b;

    (void) tag;
    (void) len;

    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &user) != 0)
	return;
    if (user->level < LEVEL_MODERATOR)
    {
	if (ISUSER (con))
	    permission_denied (con);
	return;
    }
    for (list = &Bans; *list; list = &(*list)->next)
    {
	b = (*list)->data;
	if (!strcasecmp (pkt, b->target))
	{
	    tmpList = *list;
	    *list = (*list)->next;
	    FREE (tmpList);
	    notify_mods ("%s removed ban on %s", user->nick, b->target);
	    pass_message_args (con, tag, ":%s %s", user->nick, b->target);
	    free_ban (b);
	    break;
	}
    }
    if (ISUSER (con))
	send_cmd (con, MSG_SERVER_NOSUCH, "There is no ban on %s", pkt);
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
	if (ban->type == BAN_IP)
	    send_cmd (con, MSG_SERVER_IP_BANLIST /* 616 */ ,
		      "%s %s \"%s\" %ld", ban->target, ban->setby,
		      NONULL (ban->reason), ban->when);
    }
    for (list = Bans; list; list = list->next)
    {
	ban = list->data;
	if (ban->type == BAN_USER)
	    send_cmd (con, MSG_SERVER_NICK_BANLIST /* 626 */ , "%s",
		      ban->target);
    }
    send_cmd (con, MSG_CLIENT_BANLIST /* 615 */ , "");
}

static int
ip_glob_match (const char *pattern, const char *ip)
{
    int l;

    ASSERT (pattern != 0);
    ASSERT (ip != 0);
    /* if `pattern' ends with a `.', we ban an entire subclass */
    l = strlen (pattern);
    ASSERT (l > 0);
    if (pattern[l - 1] == '.')
	return ((strncmp (pattern, ip, l) == 0));
    else
	return ((strcmp (pattern, ip) == 0));
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
	    send_cmd (con,
		      (type == BAN_IP) ? MSG_SERVER_ERROR : MSG_SERVER_NOSUCH,
		      "You are banned from this server: %s",
		      NONULL (ban->reason));
	    if (type == BAN_IP)
		notify_mods
		    ("Connection attempt from banned hosts %s (%s): %s",
		     target, ban->target, NONULL (ban->reason));
	    else
		notify_mods ("Connection from banned user %s (%s): %s",
			     target, my_ntoa (con->ip), NONULL (ban->reason));
	    con->destroy = 1;
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

    if ((fp = fopen (SHAREDIR "/bans", "w")) == 0)
    {
	logerr ("save_bans", "fopen");
	return -1;
    }
    for (list = Bans; list; list = list->next)
    {
	b = list->data;
	if (b->type == BAN_IP)
	    fprintf (fp, "%s %s %d \"%s\"\n", b->target, b->setby,
		     (int) b->when, NONULL (b->reason));
	else
	    fprintf (fp, "%s\n", b->target);
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
    char *av[4];

    if (!(fp = fopen (SHAREDIR "/bans", "r")))
    {
	logerr ("load_bans", "fopen");
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
	if (ac == 4)
	{
	    b->type = BAN_IP;
	    b->setby = STRDUP (av[1]);
	    b->when = atol (av[2]);
	    if (*av[3])
		b->reason = STRDUP (av[3]);
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
