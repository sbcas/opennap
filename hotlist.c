/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"
#include "debug.h"

/* packet contains: <user> */
HANDLER (add_hotlist)
{
    HOTLIST *hotlist;
    USER *user;
    int i;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("add_hotlist");

    /* check to see if there is an existing global hotlist entry for this
       user */
    hotlist = hash_lookup (Hotlist, pkt);
    if (!hotlist)
    {
	/* no hotlist, create one */
	hotlist = new_hotlist ();
	hotlist->nick = STRDUP (pkt);
	hash_add (Hotlist, hotlist->nick, hotlist);
    }

    /* make sure this user isn't already listed */
    for (i = 0; i < hotlist->numusers; i++)
    {
	if (hotlist->users[i] == con)
	    return; /* already present */
    }

    /* add this user to the list of users waiting for notification */
    hotlist->users = array_add (hotlist->users, &hotlist->numusers, con);

    /* add the hotlist entry to this particular users list */
    con->hotlist = array_add (con->hotlist, &con->hotlistsize, hotlist);

    /* ack the user who requested this */
    /* this seems unnecessary, but its what the official server does... */
    send_cmd (con, MSG_SERVER_HOTLIST_ACK, "%s", hotlist->nick);

    /* check to see if this user is on so the client is notified
       immediately */
    user = hash_lookup (Users, hotlist->nick);
    if (user)
    {
	send_cmd (con, MSG_SERVER_USER_SIGNON, "%s %d", user->nick,
	    user->speed);
    }
}

/* packet contains: <user> */
HANDLER (remove_hotlist)
{
    int i;
    HOTLIST *h = 0;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("remove_hotlist");

    /* find the user in this user's hotlist */
    for (i = 0; i < con->hotlistsize; i++)
    {
	if (strcmp (con->hotlist[i]->nick, pkt) == 0)
	{
	    h = con->hotlist[i];
	    break;
	}
    }
    if (!h)
    {
	log ("remove_hotlist(): user %s is not on %s's hotlist", pkt,
	    con->user->nick);
	return; /* not found */
    }

    /* remove target user from issuing user's list */
    con->hotlist = array_remove (con->hotlist, &con->hotlistsize, h);

    /* remove issuing user from the global list to notify */
    h->users = array_remove (h->users, &h->numusers, con);

    /* if no more users are waiting for notification, destroy the entry */
    if (h->numusers == 0)
	hash_remove (Hotlist, h->nick);
}

void
free_hotlist (HOTLIST *h)
{
    ASSERT (validate_hotlist (h));
    FREE (h->nick);
    if (h->users)
	FREE (h->users);
    FREE (h);
}
