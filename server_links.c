/* Copyright (C) 2000 edwards@bitchx.dimension6.com
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   Modified by drscholl@users.sourceforge.net 2/25/2000.

   $Id$ */

#include <string.h>
#include "opennap.h"
#include "debug.h"

/* process client request for server links */
/* 10112 [ :<user> ] [ <server> ] */
HANDLER (server_links)
{
    USER *user;
    LIST *list;
    CONNECTION *serv;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &user) != 0)
	return;
    ASSERT (validate_user (user));

    if (!*pkt || !strcasecmp (Server_Name, pkt))
    {
	for (list = Servers; list; list = list->next)
	{
	    serv = list->data;
	    if (serv->recvbuf)
		send_user (user, MSG_SERVER_LINKS, "%s %d %d %d %d",
			   serv->host, serv->port, serv->recvbuf->datamax,
			   serv->recvbuf->datasize, serv->recvbuf->consumed);
	    else
		send_user (user, MSG_SERVER_LINKS, "%s %d 0 0 0",
			   serv->host, serv->port);
	    send_user (user, MSG_SERVER_LINKS, "");
	}
    }
    else
	pass_message_args (con, tag, ":%s %s", user->nick, pkt);
}
