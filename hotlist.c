/* Copyright (C) 2000 drscholl@sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include "opennap.h"
#include "debug.h"

/* packet contains: <user> */
void
add_hotlist (CONNECTION *con, char *pkt)
{
    HOTLIST *hotlist;

    ASSERT (VALID (con));
    if (con->class != CLASS_USER)
    {
	log ("add_hotlist(): only USER class may issue this command");
	return;
    }

    /* check to see if there is an existing global hotlist entry for this
       user */
    hotlist = hash_lookup (Hotlist, pkt);
    if (!hotlist)
    {
	/* no hotlist, create one */
	hotlist = CALLOC (1, sizeof (HOTLIST));
	hotlist->nick = STRDUP (pkt);
	hash_add (Hotlist, hotlist->nick, hotlist);
    }

    /* add this user to the list of users waiting for notification */
    hotlist->users = array_add (hotlist->users, &hotlist->numusers,
	con->user);

    /* add the hotlist entry to this particular users list */
    con->hotlist = array_add (con->hotlist, &con->hotlistsize, hotlist);

    /* ack the user who requested this */
    /* this seems unnecessary, but its what the official server does... */
    send_cmd (con, MSG_SERVER_HOTLIST_ACK, "%s", hotlist->nick);
}

/* packet contains: <user> */
void
remove_hotlist (CONNECTION *con, char *pkt)
{
    int i;
    HOTLIST *h = 0;

    ASSERT (VALID (con));
    if (con->class != CLASS_USER)
    {
	log ("remove_hotlist(): only USER class may issue this command");
	return;
    }

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
    array_remove (con->hotlist, &con->hotlistsize, h);

    /* remove issuing user from the global list to notify */
    array_remove (h->users, &h->numusers, con);

    /* if no more users are waiting for notification, destroy the entry */
    if (h->numusers == 0)
	hash_remove (Hotlist, h->nick);
}

void
free_hotlist (HOTLIST *h)
{
    FREE (h->nick);
    if (h->users)
	FREE (h->users);
    FREE (h);
}
