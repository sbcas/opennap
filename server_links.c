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
	send_cmd (con, MSG_SERVER_LINKS, "%s %s 0", Server_Name, serv->host);
    }
    /* dump remote servers */
    for (list = Server_Links; list; list = list->next)
    {
	slink = list->data;
	send_cmd (con, MSG_SERVER_LINKS, "%s %s %d", slink->server,
		slink->peer, slink->hops);
    }
    /* terminate the list */
    send_cmd (con, MSG_SERVER_LINKS, "");
}
