/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "opennap.h"
#include "debug.h"

/* called when receiving a global message */
/* [ <nick> ] <message> */
HANDLER (announce)
{
    int i, l;
    USER *user;

    ASSERT (validate_connection (con));

    if (con->class == CLASS_USER)
	user = con->user;
    else
    {
	char *ptr = pkt;
	ASSERT (con->class == CLASS_SERVER);
	pkt = strchr (ptr, ' ');
	if (!pkt)
	{
	    log ("announce(): too few arguments in server message");
	    return;
	}
	*pkt++ = 0;
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
	if (con->class == CLASS_USER)
	    permission_denied (con);
	return;
    }

    set_tag (Buf, MSG_SERVER_ANNOUNCE);
    snprintf (Buf + 4, sizeof (Buf) - 4, "%s %s", user->nick, pkt);
    l = strlen (Buf + 4);
    set_len (Buf, l);
    l += 4;

    /* pass the message to our peer servers if a local user sent it */
    if (con->class == CLASS_USER && Num_Servers)
	pass_message (con, Buf, l);

    /* broadcast the message to our local users */
    for (i = 0; i < Num_Clients; i++)
    {
	if (Clients[i] && Clients[i]->class == CLASS_USER)
	    queue_data (Clients[i], Buf, l);
    }
}

/* 628 [ <nick> ] <message> */
/* send a message to all mods+ */
HANDLER (wallop)
{
    char *ptr;
    int i;

    ASSERT (validate_connection (con));
    if (con->class == CLASS_USER)
    {
	ASSERT (validate_user (con->user));
	if (con->user->level < LEVEL_MODERATOR)
	{
	    permission_denied (con);
	    return;
	}
	if (Num_Servers)
	    pass_message_args (con, MSG_SERVER_ANNOUNCE, "%s %s",
		con->user->nick, pkt);
	ptr = con->user->nick;
    }
    else
    {
	ptr = pkt;
	pkt = strchr (pkt, ' ');
	if (!pkt)
	{
	    log ("wallop(): malformed message from %s", pkt);
	    return;
	}
	*pkt++ = 0;
    }

    /* deliver message to local users */
    for (i = 0; i < Num_Clients; i++)
    {
	if (Clients[i] && Clients[i]->class == CLASS_USER &&
	    Clients[i]->user->level >= LEVEL_MODERATOR)
	    send_cmd (Clients[i], MSG_SERVER_ANNOUNCE, "%s %s", ptr, pkt);
    }
}
