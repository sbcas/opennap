/* Copyright (C) 2000 edwards@bitchx.dimension6.com
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   Modified by drscholl@users.sourceforge.net 2/25/2000.

   $Id$ */

#include "opennap.h"
#include "debug.h"

/* <user> */
HANDLER (server_usage)
{
    USER *user;
    int mem_used;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &user) != 0)
        return;

    if (user->level < LEVEL_ADMIN)
    {
        if (con->class == CLASS_USER)
            permission_denied (con);
        return; /* no privilege */
    }
    
    mem_used = MEMORY_USED;

    send_cmd (user->con, MSG_SERVER_USAGE_STATS, "%d %d %d %d %d %d",
	Num_Clients, Num_Servers, Num_Files,
	Num_Gigs, Channels->dbsize, mem_used);
}
