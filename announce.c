/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "opennap.h"
#include "debug.h"

/* called when receiving a global message */
/* [ :<nick> ] <message> */
HANDLER (announce)
{
    int i, l;
    USER *user;

    ASSERT (VALID (con));

    if (pop_user (con, &pkt, &user) != 0)
	return;

    /* check to see that the user has privileges */
    if ((user->flags & FLAG_ADMIN) == 0)
    {
	log ("announce(): %s is not admin", user->nick);
	return;
    }

    log ("announce(): %s sent a global message", user->nick);

    /* I'm not sure if this is right.  There obviously has to be some sort of
       different message when actually sending the message to the affected
       users, but I can't get nap v0.8 to display this message */

    set_tag (Buf, MSG_SERVER_ANNOUNCE);
    snprintf (Buf + 4, sizeof (Buf) - 4, "%s %s", user->nick, pkt);
    l = strlen (Buf + 4);
    set_len (Buf, l);
    l+=4;

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
