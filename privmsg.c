/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdio.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <string.h>
#include "opennap.h"
#include "debug.h"

/* loopback command for allowing mods using the windows client to execute
   opennap comamnds */
static void
operserv (CONNECTION * con, char *pkt)
{
    char *cmd = next_arg (&pkt);
    unsigned short tag, len;
    char ch = 0;

    if (!strcasecmp ("chanlevel", cmd))
	tag = MSG_CLIENT_CHANNEL_LEVEL;
    else if (!strcasecmp ("links", cmd))
	tag = MSG_CLIENT_LINKS;
    else if (!strcasecmp ("stats", cmd))
	tag = MSG_CLIENT_USAGE_STATS;
    else if (!strcasecmp ("connect", cmd))
	tag = MSG_CLIENT_CONNECT;
    else if (!strcasecmp ("disconnect", cmd))
	tag = MSG_CLIENT_DISCONNECT;
    else if (!strcasecmp ("killserver", cmd))
	tag = MSG_CLIENT_KILL_SERVER;
    else if (!strcasecmp ("register", cmd))
	tag = MSG_CLIENT_REGISTER_USER;
    else if (!strcasecmp ("chanlimit", cmd))
	tag = MSG_CLIENT_CHANNEL_LIMIT;
    else if (!strcasecmp ("kick", cmd))
	tag = MSG_CLIENT_KICK_USER;
    else if (!strcasecmp ("usermode", cmd))
	tag = MSG_CLIENT_USER_MODE;
    else if (!strcasecmp ("config", cmd))
	tag = MSG_CLIENT_SERVER_CONFIG;
    else if (!strcasecmp ("reconfig", cmd))
	tag = MSG_CLIENT_SERVER_RECONFIG;
    else if (!strcasecmp ("cban", cmd))
	tag = MSG_CLIENT_CHANNEL_BAN;
    else if (!strcasecmp ("cunban", cmd))
	tag = MSG_CLIENT_CHANNEL_UNBAN;
    else if (!strcasecmp ("cbanlist", cmd))
	tag = MSG_CLIENT_CHANNEL_BAN_LIST;
    else if (!strcasecmp ("cbanclear", cmd))
	tag = MSG_CLIENT_CHANNEL_CLEAR_BANS;
    else if (!strcasecmp ("cloak", cmd))
	tag = MSG_CLIENT_CLOAK;
    else
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "Unknown OperServ command: %s",
		  cmd);
	return;
    }
    if (pkt)
	len = strlen (pkt);
    else
    {
	/* most of the handler routines expect `pkt' to be non-NULL so pass
	   a dummy value here */
	pkt = &ch;
	len = 0;
    }
    dispatch_command (con, tag, len, pkt);
}

/* handles private message commands */
/* [ :<nick> ] <user> <text> */
HANDLER (privmsg)
{
    char *ptr;
    USER *sender, *user /* recip */ ;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    ptr = pkt;			/* save the start offset of pkt for length check */
    if (pop_user (con, &pkt, &sender) != 0)
	return;
    ASSERT (validate_user (sender));

    /* prevent DoS attack againt windows napster client */
    if (len - (pkt - ptr) > 180)
    {
	log ("privmsg(): truncated %d byte message from %s", len,
	     sender->nick);
	pkt[180] = 0;
    }

    /* check to see if the recipient of the message is local */
    ptr = next_arg_noskip (&pkt);
    if (!pkt)
    {
	unparsable (con);
	return;
    }

    if (ISUSER (con) && sender->level > LEVEL_USER &&
	!strcasecmp (ptr, "operserv"))
    {
	operserv (con, pkt);
	return;
    }

    /* find the recipient */
    user = hash_lookup (Users, ptr);
    if (!user)
    {
	if (ISUSER (con))
	    nosuchuser (con, ptr);
	return;
    }

    /*  locally connected user */
    if (ISUSER (user->con))
    {
	/* check to make sure this user is not ignored */
	if (!is_ignoring (user->con->uopt->ignore, sender->nick))
	{
	    /* reconstitute the message */
	    send_cmd (user->con, MSG_CLIENT_PRIVMSG, "%s %s", sender->nick,
		      pkt);
	}
	else
	{
	    /* notify the sender they are being ignored */
	    send_user (sender, MSG_SERVER_NOSUCH, "%s is ignoring you",
		       user->nick);
	}
    }
    else
    {
	/* pass the message on to our peers since the recipient isn't
	   local.  we know which server the client is behind, so we just
	   need to send one copy */
	ASSERT (user->con->class == CLASS_SERVER);
	send_cmd (user->con, MSG_CLIENT_PRIVMSG, ":%s %s %s",
		  sender->nick, user->nick, pkt);
    }
}

/* 320
   list ignored users */
HANDLER (ignore_list)
{
    int n = 0;
    LIST *list;

    (void) len;
    (void) pkt;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("ignore_list");
    for (list = con->uopt->ignore; list; list = list->next, n++)
	send_cmd (con, MSG_SERVER_IGNORE_ENTRY /* 321 */, "%s", list->data);
    send_cmd (con, tag, "%d", n);
}

/*  322 <user>
    add user to ignore list */
HANDLER (ignore)
{
    LIST *list;

    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("ignore_add");
    /*ensure that this user is not already on the ignore list */
    for (list = con->uopt->ignore; list; list = list->next)
	if (!strcasecmp (pkt, list->data))
	{
	    send_cmd(con,MSG_SERVER_ALREADY_IGNORED,"%s",pkt);
	    return;		/*already added */
	}
    list = MALLOC (sizeof (LIST));
    list->data = STRDUP (pkt);
    list->next = con->uopt->ignore;
    con->uopt->ignore = list;
    send_cmd (con, tag, "%s", pkt);
}

/* 323 <user>
   unignore user */
HANDLER (unignore)
{
    LIST **list, *tmpList;

    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("ignore_add");
    for (list = &con->uopt->ignore; *list; list = &(*list)->next)
    {
	if (!strcasecmp (pkt, (*list)->data))
	{
	    send_cmd (con, tag, "%s", pkt);
	    tmpList = *list;
	    *list = (*list)->next;
	    FREE (tmpList->data);
	    FREE (tmpList);
	    return;
	}
    }
    send_cmd (con, MSG_SERVER_NOT_IGNORED /* 324 */, "%s", pkt);
}

/* 326
   clear user's ignore list */
HANDLER (clear_ignore)
{
    int n;

    (void) len;
    (void) pkt;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("clear_ignore");
    n = list_count (con->uopt->ignore);
    list_free (con->uopt->ignore, free_pointer);
    con->uopt->ignore = 0;
    send_cmd (con, tag, "%d", n);
}
