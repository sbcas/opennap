/* Copyright (C) 2000 edwards@bitchx.dimension6.com
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   Modified by drscholl@users.sourceforge.net 2/25/2000.

   $Id$ */

#include <string.h>
#include "opennap.h"
#include "debug.h"

/* 10112 */
/* process client request for server links */
HANDLER (server_links)
{
    LIST *list;
    LINK *slink;
    CONNECTION *serv;

    (void) tag;
    (void) len;
    (void) pkt;
    CHECK_USER_CLASS ("server_links");
    ASSERT (validate_connection (con));

    /* first dump directly connected servers */
    for (list = Servers; list; list = list->next)
    {
	serv = list->data;
	send_cmd (con, MSG_SERVER_LINKS, "%s %d %s %d 0 %d",
		  Server_Name, get_local_port (serv->fd), serv->host,
		  serv->port, serv->recvbuf->datamax);
    }
    /* dump remote servers */
    for (list = Server_Links; list; list = list->next)
    {
	slink = list->data;
	send_cmd (con, MSG_SERVER_LINKS, "%s %d %s %d %d -1", slink->server,
		  slink->port, slink->peer, slink->peerport, slink->hops);
    }
    /* terminate the list */
    send_cmd (con, MSG_SERVER_LINKS, "");
}

/* 750 [ :<sender> ] <server> [ <args> ] */
HANDLER (ping_server)
{
    USER *sender;
    char *server;

    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &sender))
	return;
    if (!pkt)
    {
	unparsable (con);
	return;
    }
    server = next_arg (&pkt);
    /* if no server is specified, assume a ping to the local server */
    if (ISUSER(con) && !is_server(server))
	send_cmd(con,tag,"%s%s%s",server,pkt?" ":"", NONULL(pkt));
    else if (!strcasecmp (Server_Name, server))
	send_user (sender, tag, "%s %s", Server_Name, NONULL (pkt));
    else
	pass_message_args (con, tag, ":%s %s %s", sender->nick, server,
			   NONULL (pkt));
}
