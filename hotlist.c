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

    /* check to see if this user is over the hotlist limit */
    if(Max_Hotlist > 0 && list_count(con->uopt->hotlist) > Max_Hotlist)
    {
	send_cmd(con,MSG_SERVER_NOSUCH,"hotlist is limited to %d entries",
		 Max_Hotlist);
	return;
    }
    /* check to see if there is an existing global hotlist entry for this
       user */
    hotlist = hash_lookup (Hotlist, pkt);
    if (!hotlist)
    {
	if(invalid_nick(pkt))
	{
	    invalid_nick_msg(con);
	    return;
	}
	/* no hotlist, create one */
	hotlist = CALLOC (1, sizeof (HOTLIST));
	if (hotlist)
	    hotlist->nick = STRDUP (pkt);
	if (!hotlist || !hotlist->nick)
	{
	    OUTOFMEMORY ("add_hotlist");
	    return;		/* no memory */
	}
#if DEBUG
	hotlist->magic = MAGIC_HOTLIST;
#endif
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
    list = MALLOC (sizeof (LIST));
    if (!list)
    {
	OUTOFMEMORY ("add_hotlist");
	return;
    }
    list->data = con;
    list->next = hotlist->users;
    hotlist->users = list;

    /* add the hotlist entry to this particular users list */
    list = MALLOC (sizeof (LIST));
    if (!list)
    {
	OUTOFMEMORY ("add_hotlist");
	return;
    }
    list->data = hotlist;
    list->next = con->uopt->hotlist;
    con->uopt->hotlist = list;

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
    HOTLIST *hotlist;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("remove_hotlist");
    hotlist = hash_lookup (Hotlist, pkt);
    if (!hotlist)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "user is not in your hotlist");
	return;
    }
    ASSERT (validate_hotlist (hotlist));
    /* remove the hotlist entry from the user's personal list */
    con->uopt->hotlist = list_delete (con->uopt->hotlist, hotlist);
    /* remove the user from the global hotlist */
    hotlist->users = list_delete (hotlist->users, con);
    /* if there are no more waiting users, destroy the global hotlist entry */
    if (!hotlist->users)
	hash_remove (Hotlist, hotlist->nick);
}

void
free_hotlist (HOTLIST * h)
{
    ASSERT (validate_hotlist (h));
    ASSERT (h->users == 0);	/* shouldnt free this entry unless there are
				   no users left.  this will cause a harmless
				   assertion when cleaning up, however */
    list_free (h->users, 0);
    FREE (h->nick);
    FREE (h);
}
