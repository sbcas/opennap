/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <string.h>
#include <unistd.h>
#include "opennap.h"
#include "debug.h"

static void
server_split (void *puser, void *pcon)
{
    USER *user = (USER *) puser;
    CONNECTION *con = (CONNECTION *) pcon;

    ASSERT (VALID (user));
    ASSERT (VALID (con));
    if (user->serv == con)
	hash_remove (Users, user->nick);
}

void
remove_connection (CONNECTION *con)
{
    ASSERT (VALID (con));

    close (con->fd);

    if (con->class == CLASS_USER)
    {
	int i;

	/* remove user from global list */
	ASSERT (VALID (con->user));
	hash_remove (Users, con->user->nick);

	/* if this user had hotlist entries, remove them from the lists */
	for (i = 0; i < con->hotlistsize; i++)
	{
	    array_remove (con->hotlist[i]->users, &con->hotlist[i]->numusers,
		con);
	    if (con->hotlist[i]->numusers == 0)
		hash_remove (Hotlist, con->hotlist[i]->nick);
	}
	if (con->hotlist)
	    FREE (con->hotlist);
    }
    else if (con->class == CLASS_SERVER)
    {
	/* if we detect that a server has quit, we need to remove all users
	   that were behind this server.  we do this by searching the User
	   hash table for entries where the .serv member is this connection.
	   we also need to send QUIT messages for each user to any other
	   servers we have */

	/* first off, lets remove this server from the Servers list so
	   that pass_message() doesnt try to send message back through this
	   server (although we could just pass this connection to it and it
	   would avoid sending it) */

	log ("remove_connection(): server split detected (%s)", con->host);

	array_remove (Servers, &Num_Servers, con);

	/* remove all users that were behind this server from the hash table.
	   this should be an infrequent enough occurance than iterating the
	   entire hash table does not need to be optimized the way we split
	   out the server connections. */
	hash_foreach (Users, server_split, con);

    }

    /* destroy authentication information */
    if (con->sendernonce)
	FREE (con->sendernonce);
    if (con->nonce)
	FREE (con->nonce);

    /* common data */
    if (con->host)
	FREE (con->host);
    if (con->sendbufmax)
	FREE (con->sendbuf);
    if (con->recvdata)
	FREE (con->recvdata);
    /* just create a hole where this client was for now.  the main() event
       loop will fill in the holes when appropriate.  we don't do this
       here because there are many places, such as kill_user() where a
       connection could be removed, and it would reak havoc on the main
       event loop which expects for the Clients[] array not to change */
    Clients[con->id] = 0;

    FREE (con);
}
