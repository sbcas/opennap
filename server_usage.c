/* Copyright (C) 2000 edwards@bitchx.dimension6.com
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   Modified by drscholl@users.sourceforge.net 2/25/2000.

   $Id$ */

#include <time.h>
#include <string.h>
#include "opennap.h"
#include "debug.h"

/* 10115 [ :<user> ] [ <server> ] */
HANDLER (server_usage)
{
    USER *user;
    int mem_used, numServers;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("server_usage");
    if (pop_user (con, &pkt, &user) != 0)
	return;

    if (!*pkt || !strcasecmp (pkt, Server_Name))
    {
	mem_used = MEMORY_USED;

	numServers = list_count (Servers);
	send_user (user, MSG_SERVER_USAGE_STATS,
		  "%d %d %d %d %u %d %d %d %d %d",
		  Num_Clients - numServers, numServers, Users->dbsize,
		  Num_Files, Num_Gigs, Channels->dbsize, Server_Start,
		  time (0) - Server_Start, mem_used, User_Db->dbsize);
    }
    else
	pass_message_args (con, tag, ":%s %s", user->nick, pkt);
}
