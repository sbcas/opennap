/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

/* user request to change the data port they are listening on.
   703 [ :<user> ] <port> */
HANDLER (change_data_port)
{
    int port;
    USER *user;

    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &user) != 0)
	return;
    ASSERT (validate_user (user));
    port = atoi (pkt);

    /* the official server doesn't seem to check the value sent, so this
       error is unique to this implementation */
    if (port >= 0 && port <= 65535)
    {
	user->port = port;
	if (con->class == CLASS_USER && Num_Servers)
	{
	    pass_message_args (con, MSG_CLIENT_CHANGE_DATA_PORT, ":%s %d",
		    user->nick, user->port);
	}
    }
    else if (con->class == CLASS_USER)
	send_cmd (con, MSG_SERVER_NOSUCH, "invalid data port");
}

/* 700 [ :<user> ] <speed> */
/* client is changing link speed */
HANDLER (change_speed)
{
    USER *user;
    int spd;

    ASSERT (VALID (con));
    if (pop_user (con, &pkt, &user) != 0)
	return;
    spd = atoi (pkt);
    if (spd >= 0 && spd <= 10)
    {
	user->speed = spd;
	/* if a local user, pass this info to our peer servers */
	if (con->class == CLASS_USER && Num_Servers)
	{
	    pass_message_args (con, MSG_CLIENT_CHANGE_SPEED, ":%s %d",
		    user->nick, spd);
	}
    }
    else if (con->class == CLASS_USER)
	send_cmd (con, MSG_SERVER_NOSUCH, "invalid speed");
}
