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
server_split (USER * user, CONNECTION * con)
{
    ASSERT (validate_user (user));
    ASSERT (validate_connection (con));
    ASSERT (con->class == CLASS_SERVER);

    /* check to see if this user was behind the server that just split */
    if (user->con == con)
    {
	/* on split, we have to notify our peer servers that this user
	   is no longer online */
	pass_message_args (con, MSG_CLIENT_QUIT, "%s", user->nick);
	/* remove the user from the hash table */
	hash_remove (Users, user->nick);
    }
}

void
remove_connection (CONNECTION * con)
{
    HOTLIST *hotlist;

    ASSERT (validate_connection (con));

    /* close socket */
    CLOSE (con->fd);

    /* if this connection had any pending searches, cancel them */
    cancel_search (con);

    if (ISUSER (con))
    {
	LIST *u;

	/* remove user from global list, calls free_user() indirectly */
	ASSERT (validate_user (con->user));
	hash_remove (Users, con->user->nick);

	/* if this user had hotlist entries, remove them from the lists */
	for (u = con->uopt.hotlist; u; u = u->next)
	{
	    hotlist = u->data;
	    ASSERT (validate_hotlist (hotlist));
	    hotlist->users = list_delete (hotlist->users, con);
	    if (!hotlist->users)	/* no more users, free entry */
		hash_remove (Hotlist, hotlist->nick);
	}

	list_free (con->uopt.hotlist, 0);
	con->uopt.hotlist = 0;	/* need to set this to avoid asserting in
				   cancel_search() */

    }
    else if (ISSERVER (con))
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
	notify_mods ("Server %s has quit.", con->host);
	/* notify our peers this server has quit */
	pass_message_args (con, MSG_SERVER_QUIT, ":%s %s", Server_Name,
		con->host);
	/* if this server was linked to other servers, remove the information
	   we have on those links */
	remove_links (con->host);

	Servers = list_delete (Servers, con);

	/* remove all users that were behind this server from the hash table.
	   this should be an infrequent enough occurance than iterating the
	   entire hash table does not need to be optimized the way we split
	   out the server connections. */
	hash_foreach (Users, (hash_callback_t) server_split, con);

#if HAVE_LIBZ
	finalize_compress (con->sopt);
#endif
	buffer_free (con->sopt->outbuf);
	FREE (con->sopt);
    }
    else
    {
	ASSERT (con->class == CLASS_UNKNOWN);
	if (con->server_login)
	{
	    if (con->opt.auth)
	    {
		if (con->opt.auth->nonce)
		    FREE (con->opt.auth->nonce);
		if (con->opt.auth->sendernonce)
		    FREE (con->opt.auth->sendernonce);
		FREE (con->opt.auth);
	    }
	}
    }

    /* common data */
    if (con->host)
	FREE (con->host);
    buffer_free (con->sendbuf);
    buffer_free (con->recvbuf);
    Clients[con->id] = 0;
    Num_Clients--;

    FREE (con);
}
