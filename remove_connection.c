/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

static void
server_split (USER *user, CONNECTION *con)
{
    ASSERT (validate_user (user));
    ASSERT (validate_connection (con));

    /* check to see if this user was behind the server that just split */
    if (user->serv == con)
    {
	/* on split, we have to notify our peer servers that this user
	   is no longer online */
	if (Num_Servers)
	    pass_message_args (con, MSG_CLIENT_QUIT, "%s", user->nick);
	/* remove the user from the hash table */
	hash_remove (Users, user->nick);
    }
}

void
remove_connection (CONNECTION *con)
{
    ASSERT (validate_connection (con));

    /* flush anything left in the queue */
    send_queued_data (con);

    /* close socket */
    close (con->fd);

    if (con->class == CLASS_USER)
    {
	int i;

	/* remove user from global list */
	ASSERT (validate_user (con->user));
	hash_remove (Users, con->user->nick);

	/* if this user had hotlist entries, remove them from the lists */
	for (i = 0; i < con->hotlistsize; i++)
	{
	    con->hotlist[i]->users = array_remove (con->hotlist[i]->users,
		    &con->hotlist[i]->numusers, con);
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
	notify_mods ("server %s has split.", con->host);

	Servers = array_remove (Servers, &Num_Servers, con);

	/* remove all users that were behind this server from the hash table.
	   this should be an infrequent enough occurance than iterating the
	   entire hash table does not need to be optimized the way we split
	   out the server connections. */
	hash_foreach (Users, (hash_callback_t) server_split, con);
    }

    /* destroy authentication information */
    if (con->sendernonce)
	FREE (con->sendernonce);
    if (con->nonce)
	FREE (con->nonce);

    /* common data */
    if (con->host)
	FREE (con->host);
    buffer_free (con->sendbuf);
    buffer_free (con->recvbuf);
#if HAVE_LIBZ
    if (con->zip)
	finalize_compress (con->zip);
#endif

    /* just create a hole where this client was for now.  the main() event
       loop will fill in the holes when appropriate.  we don't do this
       here because there are many places, such as kill_user() where a
       connection could be removed, and it would reak havoc on the main
       event loop which expects for the Clients[] array not to change */
    Clients[con->id] = 0;

    FREE (con);
}
