/* Copyright (C) 2000 edwards@bitchx.dimension6.com
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   Modified by drscholl@users.sourceforge.net 2/25/2000.

   $Id$ */

#include "opennap.h"
#include "debug.h"

/* process client request for server links */
/* 10112 [ :<user> ] */
HANDLER (server_links)
{
    USER *user;
    int i;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("server_links");
    if (pop_user (con, &pkt, &user) != 0)
	return;
    ASSERT (validate_user (user));

    if (user->level < LEVEL_MODERATOR)
    {
	if (con->class == CLASS_USER)
	    permission_denied (con);
	return;			/* no privilege */
    }

    for (i = 0; i < Num_Servers; i++)
    {
	if (Servers[i]->recvbuf)
	    send_cmd (con, MSG_SERVER_LINKS, "%s %d %d %d %d",
		Servers[i]->host, Servers[i]->port,
		Servers[i]->recvbuf->datamax,
		Servers[i]->recvbuf->datasize,
		Servers[i]->recvbuf->consumed);
	else
	    send_cmd (con, MSG_SERVER_LINKS, "%s %d 0 0 0",
		Servers[i]->host, Servers[i]->port,
		Servers[i]->recvbuf->datamax,
		Servers[i]->recvbuf->datasize,
		Servers[i]->recvbuf->consumed);
	/*
	not yet.
	pass_message_args (con, MSG_CLIENT_LINK_REQUEST, ":%s", user->nick);
	 */
    }

    send_cmd (con, MSG_SERVER_LINKS, "");
}
