/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

/* packet contains: <user> */
HANDLER (add_hotlist)
{
    HOTLIST *hotlist;
    USER *user;
    LIST *list;

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
	hotlist = CALLOC (1, sizeof (HOTLIST));
#if DEBUG
	hotlist->magic = MAGIC_HOTLIST;
#endif
	if(hotlist)
	    hotlist->nick = STRDUP (pkt);
	if (!hotlist || !hotlist->nick)
	{
	    OUTOFMEMORY ("add_hotlist");
	    return;	/* no memory */
	}
	if (hash_add (Hotlist, hotlist->nick, hotlist))
	{
	    FREE (hotlist->nick);
	    FREE (hotlist);
	    return;
	}
    }
    ASSERT (validate_hotlist (hotlist));

    /* make sure this user isn't already listed */
    if (list_find (hotlist->users, con))
	return;

    /* add this user to the list of users waiting for notification */
    list = CALLOC (1, sizeof (LIST));
    if (!list)
    {
	OUTOFMEMORY ("add_hotlist");
	return;
    }
    list->data = con;
    hotlist->users = list_append (hotlist->users, list);

    /* add the hotlist entry to this particular users list */
    list = CALLOC (1, sizeof (LIST));
    if (!list)
    {
	OUTOFMEMORY ("add_hotlist");
	return;
    }
    list->data = hotlist;
    con->uopt.hotlist = list_append (con->uopt.hotlist, list);

    /* ack the user who requested this */
    /* this seems unnecessary, but its what the official server does... */
    send_cmd (con, MSG_SERVER_HOTLIST_ACK, "%s", hotlist->nick);

    /* check to see if this user is on so the client is notified
       immediately */
    user = hash_lookup (Users, hotlist->nick);
    if (user)
    {
	ASSERT (validate_user (user));
	send_cmd (con, MSG_SERVER_USER_SIGNON, "%s %d", user->nick,
	    user->speed);
    }
}

/* packet contains: <user> */
HANDLER (remove_hotlist)
{
    HOTLIST *h = 0;
    LIST **list, *tmp;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("remove_hotlist");

    /* find the user in this user's hotlist */
    ASSERT (con->opt.hotlist != 0);
    for (list = &con->uopt.hotlist; *list; list = &(*list)->next)
    {
	h = (*list)->data;
	ASSERT (validate_hotlist (h));
	if (!strcasecmp (pkt, h->nick))
	{
	    tmp = *list;
	    *list = (*list)->next;
	    FREE (tmp);

	    /* remove issuing user from the global list to notify */
	    h->users = list_delete (h->users, con);
	    /* if no more users are waiting for notification, destroy
	       the entry */
	    if (!h->users)
		hash_remove (Hotlist, h->nick);
	    return;
	}
    }
    log ("remove_hotlist(): user %s is not on %s's hotlist", pkt,
	    con->user->nick);
    send_cmd (con, MSG_SERVER_NOSUCH,
	    "Could not find user %s in your hotlist.", pkt);
}

void
free_hotlist (HOTLIST *h)
{
    ASSERT (validate_hotlist (h));
    FREE (h->nick);
    list_free (h->users, 0);
    FREE (h);
}
