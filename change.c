/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

/* user request to change the data port they are listening on.
   packet contains: <port> */
HANDLER (change_data_port)
{
    int port;

    ASSERT (VALID (con));
    CHECK_USER_CLASS ("change_data_port");
    ASSERT (VALID (con->user));
    port = atoi (pkt);

    /* the official server doesn't seem to check the value sent, so this
       error is unique to this implementation */
    if (port >= 0 && port <= 65535)
	con->user->port = port;
    else
	send_cmd (con, MSG_SERVER_ERROR, "invalid data port");
}
