/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <ctype.h>
#include <string.h>
#include "opennap.h"
#include "debug.h"

/* an ip address consists of only numbers and dots */
static int
is_ip (const char *s)
{
    for(;*s;s++)
	if(!isdigit(*s) && *s != '.')
	    return 0;
    return 1;
}

void
free_ban (BAN *b)
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

    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &sender) != 0)
	return;

    /* make sure this user has privilege */
    ASSERT (validate_user (sender));
    if (sender->level < LEVEL_MODERATOR)
    {
	if (con->class == CLASS_USER)
	    permission_denied (con);
	log ("ban_user(): %s does not have ban privilege", sender->nick);
	return;
    }

    ban = pkt;
    pkt = strchr (pkt, ' ');
    if (pkt)
	*pkt++ = 0;
    /* if a local user, pass this to our peers */
    if (con->class == CLASS_USER && Num_Servers)
    {
	pass_message_args (con, MSG_CLIENT_BAN, ":%s %s %s",
		sender->nick, ban, pkt ? pkt : "");
    }

    /* create structure and add to global ban list */
    b = CALLOC (1, sizeof (BAN));
    b->target = STRDUP (ban);
    b->setby = STRDUP (sender->nick);
    /* determine if this ban is on an ip or a user */
    b->type = (is_ip (ban)) ? BAN_IP : BAN_USER;
    if (pkt)
	b->reason = STRDUP (pkt);
    else
	b->reason = STRDUP ("");
    Ban = array_add (Ban, &Ban_Size, b);
}

/* 614 [ :<sender> ] <nick|ip> */
HANDLER (unban)
{
    USER *user;
    int i;

    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &user) != 0)
	return;
    if (user->level < LEVEL_MODERATOR)
    {
	if (con->class == CLASS_USER)
	    permission_denied (con);
	return;
    }
    for (i = 0; i < Ban_Size; i++)
	if (!strcasecmp (pkt, Ban[i]->target))
	{
	    free_ban (Ban[i]);
	    if (con->class == CLASS_USER)
	    {
		if (Num_Servers)
		{
		    pass_message_args (con, MSG_CLIENT_UNBAN, ":%s %s",
			    user->nick, pkt);
		}
	    }
	    notify_mods ("%s removed the ban on %s", user->nick, pkt);
	    return;
	}
    if (con->class == CLASS_USER)
	send_cmd (con, MSG_SERVER_NOSUCH, "there is no ban on %s", pkt);
}

/* 615 */
/* show the list of current bans on the server */
HANDLER (banlist)
{
    int i;

    (void) pkt;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("banlist");
    for (i = 0; i < Ban_Size; i++)
    {
	if (Ban[i]->type == BAN_IP)
	    send_cmd (con, MSG_SERVER_IP_BANLIST /* 616 */, "%s %s \"%s\" %ld",
		    Ban[i]->target, Ban[i]->setby,
		    Ban[i]->reason ? Ban[i]->reason : "",
		    Ban[i]->when);
    }
    for (i = 0; i < Ban_Size; i++)
    {
	if (Ban[i]->type == BAN_USER)
	    send_cmd (con, MSG_SERVER_NICK_BANLIST /* 626 */, "%s", Ban[i]->target);
    }
}
