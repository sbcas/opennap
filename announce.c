/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#ifndef WIN32
#include <unistd.h>
#endif /* !WIN32 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

/* called when receiving a global message */
/* 627 [ <nick> ] <message> */
HANDLER (announce)
{
    int i, l;
    USER *user;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    if (ISUSER (con))
	user = con->user;
    else
    {
	char *ptr;

	ASSERT (ISSERVER (con));
	ptr = next_arg_noskip (&pkt);
	if (!pkt)
	{
	    log ("announce(): too few arguments in server message");
	    return;
	}
	user = hash_lookup (Users, ptr);
	if (!user)
	{
	    log ("announce(): can't find user %s", ptr);
	    return;
	}
    }

    ASSERT (validate_user (user));

    /* check to see that the user has privileges */
    if (user->level < LEVEL_ADMIN)
    {
	log ("announce(): %s is not admin", user->nick);
	if (ISUSER (con))
	    permission_denied (con);
	return;
    }

    l = form_message (Buf, sizeof (Buf), tag, "%s %s", user->nick, pkt);

    /* pass the message to our peer servers if a local user sent it */
    pass_message (con, Buf, l);

    /* broadcast the message to our local users */
    for (i = 0; i < Max_Clients; i++)
    {
	if (Clients[i] && ISUSER (Clients[i]))
	    queue_data (Clients[i], Buf, l);
    }
}

/* 628 [ <nick> ] <message> */
/* send a message to all mods+ */
HANDLER (wallop)
{
    char *ptr;
    int i, l;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (con->class == CLASS_USER)
    {
	ASSERT (validate_user (con->user));
	if (con->user->level < LEVEL_MODERATOR)
	{
	    permission_denied (con);
	    return;
	}
	ptr = con->user->nick;
    }
    else
    {
	ptr = next_arg_noskip (&pkt);
	if (!pkt)
	{
	    log ("wallop(): malformed message from %s", pkt);
	    return;
	}
    }

    l = form_message (Buf, sizeof (Buf), tag, "%s %s", ptr, pkt);
    pass_message (con, Buf, l);

    /* deliver message to local users */
    for (i = 0; i < Max_Clients; i++)
    {
	if (Clients[i] && ISUSER (Clients[i]) &&
	    Clients[i]->user->level >= LEVEL_MODERATOR &&
	    (Clients[i]->uopt->usermode & WALLOPLOG_MODE))
	    queue_data (Clients[i], Buf, l);
    }
}

/* 10021 :<server> <loglevel> "<message>" */
HANDLER (remote_notify_mods)
{
    int ac, level;
    char *av[3];

    (void) len;
    ac = split_line (av, FIELDS (av), pkt);
    if (ac < 3)
    {
	log ("remote_notify_mods(): too few parameters");
	print_args (ac, av);
	return;
    }
    level = atoi (av[1]);
    notify_mods (level, "[%s] %s", av[0] + 1, av[2]);
    pass_message_args (con, tag, ":%s %d \"%s\"", av[0] + 1, level, av[2]);
    log ("remote_notify_mods(): broadcast from %s (level %d): %s",
	 av[0] + 1, level, av[2]);
}
