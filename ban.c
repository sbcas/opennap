/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
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
    FREE (b->target);
    FREE (b->setby);
    if (b->reason)
	FREE (b->reason);
    FREE (b);
}

/* 612 [ :<sender> ] <user|ip> [ <reason> ] */
HANDLER (ban)
{
    USER *sender;
    char *ban;
    BAN *b;

    (void) tag;
    (void) len;

    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &sender) != 0)
	return;

    /* make sure this user has privilege */
    ASSERT (validate_user (sender));
    if (sender->level < LEVEL_MODERATOR)
    {
	if (con->class == CLASS_USER)
	    permission_denied (con);
	return;
    }

    ban = next_arg (&pkt);

    pass_message_args (con, MSG_CLIENT_BAN, ":%s %s %s", sender->nick, ban,
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
	Ban = array_add (Ban, &Ban_Size, b);
	notify_mods ("%s banned %s: %s", sender->nick, ban, NONULL (pkt));
	return;
    }
    while (1);

    /* we only get here on error */
    OUTOFMEMORY ("ban");
    if (b->target)
	FREE (b->target);
    if (b->setby)
	FREE (b->setby);
    if (b->reason)
	FREE (b->reason);
    if (b)
	FREE (b);
}

/* 614 [ :<sender> ] <nick|ip> */
HANDLER (unban)
{
    USER *user;
    int i;

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
    for (i = 0; i < Ban_Size; i++)
	if (!strcasecmp (pkt, Ban[i]->target))
	{
	    free_ban (Ban[i]);
	    pass_message_args (con, MSG_CLIENT_UNBAN, ":%s %s", user->nick,
			       pkt);
	    Ban_Size--;
	    notify_mods ("%s removed the ban on %s", user->nick, pkt);
	    return;
	}
    if (ISUSER (con))
	send_cmd (con, MSG_SERVER_NOSUCH, "There is no ban on %s", pkt);
}

/* 615 */
/* show the list of current bans on the server */
HANDLER (banlist)
{
    int i;

    (void) tag;
    (void) len;
    (void) pkt;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("banlist");
    for (i = 0; i < Ban_Size; i++)
    {
	if (Ban[i]->type == BAN_IP)
	    send_cmd (con, MSG_SERVER_IP_BANLIST /* 616 */ ,
		      "%s %s \"%s\" %ld", Ban[i]->target, Ban[i]->setby,
		      NONULL (Ban[i]->reason), Ban[i]->when);
    }
    for (i = 0; i < Ban_Size; i++)
    {
	if (Ban[i]->type == BAN_USER)
	    send_cmd (con, MSG_SERVER_NICK_BANLIST /* 626 */ , "%s",
		      Ban[i]->target);
    }
    send_cmd (con, MSG_CLIENT_BANLIST /* 615 */ , "");
}
