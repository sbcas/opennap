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

char *
normalize_ban(/*const*/ char *src, char *dest, int destlen)
{
    /* normalize the ban to the full user!host syntax */
    if(strchr(src, '!'))
	return src; /* already in proper format */
    else if (invalid_nick(src))
    {
	char *star;

	/* append a star if the last char is a . so that it means the same
	 * as the old-style ban
	 */
	if(*src && src[strlen(src)-1]=='.')
	    star="*";
	else
	    star="";
	snprintf(dest,destlen,"*!%s%s",src,star); /* must be an ip/dns name? */
    }
    else
	snprintf(dest,destlen,"%s!*",src); /* must be a nick */
    return dest;
}

/* 612 [ :<sender> ] <user!ip> [ "<reason>" [time] ] */
HANDLER (ban)
{
    BAN *b;
    LIST *list;
    int ac = -1;
    char *av[3], *sendernick;
    char *banptr, realban[256];
    USER *sender;
    int timeout = 0;

    (void) len;
    ASSERT (validate_connection (con));

    if(pop_user_server(con,tag,&pkt,&sendernick,&sender))
	return;
    if(sender && sender->level < LEVEL_MODERATOR)
    {
	    permission_denied (con);
	    return;
    }
    if (pkt)
	ac = split_line (av, FIELDS (av), pkt);
    if (ac < 1)
    {
	unparsable (con);
	return;
    }

    if(ac>2)
    {
	timeout = atoi (av[2]);
	if(timeout < 0)
	{
	    if(ISUSER(con))
		send_cmd(con,MSG_SERVER_NOSUCH,"invalid ban timeout");
	    return;
	}
    }

    banptr=normalize_ban(av[0], realban, sizeof(realban));

    /* check to see if this user is already banned */
    for (list = Bans; list; list = list->next)
    {
	b = list->data;
	if (!strcasecmp (banptr, b->target))
	{
	    if (ISUSER (con))
		send_cmd (con, MSG_SERVER_NOSUCH, "already banned");
	    return;
	}
    }

    if (ac > 1)
	truncate_reason (av[1]);

    pass_message_args (con, tag, ":%s %s \"%s\" %d", sendernick,
	    av[0], ac>1?av[1]:"", timeout);

    do
    {
	/* create structure and add to global ban list */
	if (!(b = CALLOC (1, sizeof (BAN))))
	    break;
	if (!(b->target = STRDUP (banptr)))
	    break;
	if (!(b->setby = STRDUP (sendernick)))
	    break;
	if (!(b->reason = STRDUP (ac > 1 ? av[1] : "")))
	    break;
	b->when = Current_Time;
	b->timeout = timeout;

	list = CALLOC (1, sizeof (LIST));
	if (!list)
	{
	    OUTOFMEMORY("ban");
	    break;
	}
	list->data = b;
	list->next = Bans;
	Bans = list;
	notify_mods (BANLOG_MODE,
		"%s banned %s%s%s%s: %s", sendernick, b->target,
		(timeout>0) ? " for " : "",
		(timeout>0) ? av[2] : "",
		(timeout>0) ? " seconds" : "",
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

/* 614 [ :<sender> ] <nick!ip> [ "<reason>" ] */
HANDLER (unban)
{
    USER *user;
    LIST **list, *tmpList;
    BAN *b;
    int ac = -1;
    char *av[2];
    char *banptr, realban[256];

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
    banptr=normalize_ban(av[0], realban, sizeof(realban));
    if (ac > 1)
	truncate_reason (av[1]);
    for (list = &Bans; *list; list = &(*list)->next)
    {
	b = (*list)->data;
	if (!strcasecmp (banptr, b->target))
	{
	    tmpList = *list;
	    *list = (*list)->next;
	    FREE (tmpList);
	    notify_mods (BANLOG_MODE, "%s removed ban on %s: %s",
			 user->nick, b->target, ac > 1 ? av[1] : "");
	    pass_message_args (con, tag, ":%s %s \"%s\"", user->nick,
		    b->target, ac>1 ? av[1]:"");
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
		  "%s %s \"%s\" %ld %d", ban->target, ban->setby,
		  ban->reason, ban->when, ban->timeout);
    }
    /* terminate the banlist */
    send_cmd (con, MSG_CLIENT_BANLIST /* 615 */ , "");
}

int
check_ban (CONNECTION * con, const char *nick, const char *host)
{
    LIST *list;
    BAN *ban;
    char mask[256];

    snprintf(mask,sizeof(mask),"%s!%s",nick,host);
    for (list = Bans; list; list = list->next)
    {
	ban = list->data;
	if((ban->timeout == 0 || ban->when + ban->timeout > Current_Time) &&
		glob_match(ban->target,mask))
	{
	    notify_mods (BANLOG_MODE,
		    "Connection from %s: %s banned: %s",
		    mask, ban->target, NONULL (ban->reason));
	    if (ISUNKNOWN (con))
	    {
		send_cmd (con, MSG_SERVER_ERROR,
			"%s banned: %s", ban->target, NONULL (ban->reason));
		con->destroy = 1;
		/* pass message along so all server mods+ see it.  only do
		   this for local users since the KILL message will serve
		   as notice otherwise */
		pass_message_args (NULL, MSG_SERVER_NOTIFY_MODS,
			":%s %d \"Connection from %s: %s banned: %s\"",
			Server_Name, BANLOG_MODE, mask,
			ban->target, NONULL (ban->reason));
	    }
	    else if (ISSERVER (con))
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
	fprintf (fp, "%s %s %d \"%s\" %d", b->target, b->setby,
		(int) b->when, b->reason, b->timeout);
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
    char *av[5], path[_POSIX_PATH_MAX];
    char *banptr, realban[256];

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
	banptr=normalize_ban(av[0],realban,sizeof(realban));
	b->target = STRDUP (banptr);
	if(!b->target)
	{
	    OUTOFMEMORY("load_bans");
	    FREE(b);
	    break;
	}
	if (ac >= 4)
	{
	    b->setby = STRDUP (av[1]);
	    b->when = atol (av[2]);
	    truncate_reason (av[3]);
	    b->reason = STRDUP (av[3]);
	    if(ac>4)
		b->timeout = atoi (av[4]);
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

/* reap expired bans from the list */
void
expire_bans (void)
{
    LIST **list, *tmp;
    BAN *b;

    list=&Bans;
    while(*list)
    {
	b=(*list)->data;
	if(b->timeout > 0 && b->when + b->timeout < Current_Time)
	{
	    tmp=*list;
	    *list=(*list)->next;
	    FREE(tmp);
	    /* make sure all servers are synched up */
	    pass_message_args(NULL,MSG_CLIENT_UNBAN,":%s %s \"expired after %d seconds\"",
		    Server_Name, b->target, b->timeout);
	    notify_mods(BANLOG_MODE,"%s removed ban on %s: expired after %d seconds",
		    Server_Name, b->target, b->timeout);
	    free_ban(b);
	    continue;
	}
	list=&(*list)->next;
    }
}
