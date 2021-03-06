/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
#include "opennap.h"
#include "debug.h"

/* packet contains: <channel> */
HANDLER (list_users)
{
    CHANNEL *chan;
    LIST *list;
    CHANUSER *chanUser;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("list_users");
    chan = hash_lookup (Channels, pkt);
    if (!chan)
    {
	nosuchchannel (con);
	return;
    }
    ASSERT (validate_channel (chan));
    /* make sure this user is on the channel */
    if (list_find (con->user->channels, chan) == 0)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "you're not on channel %s",
		  chan->name);
	return;
    }

    for (list = chan->users; list; list = list->next)
    {
	chanUser = list->data;
	ASSERT (chanUser->magic == MAGIC_CHANUSER);
	send_cmd (con, MSG_SERVER_NAMES_LIST /* 825 */ , "%s %s %d %d",
		  chan->name, chanUser->user->nick, chanUser->user->shared,
		  chanUser->user->speed);
    }

    send_cmd (con, MSG_SERVER_NAMES_LIST_END /* 830 */ , "");
}

#define ON_GFLAG_ELITE		1
#define ON_GFLAG_ADMIN		2
#define ON_GFLAG_MODERATOR	4
#define ON_GFLAG_LEECH		8
#define ON_GFLAG_MUZZLED	16
#define ON_GFLAG_CLOAKED	32

struct guldata
{
    int flags;
    char *server;
    CONNECTION *con;
};

static void
global_user_list_cb (USER * user, struct guldata *data)
{
    ASSERT (validate_user (user));
    ASSERT (data != 0);
    if (data->flags)
    {
	/* selectively display users based on user level/muzzle/cloak */
	if (!(((data->flags & ON_GFLAG_ADMIN) && user->level == LEVEL_ADMIN) ||
		    ((data->flags & ON_GFLAG_ELITE) && user->level == LEVEL_ELITE) ||
		    ((data->flags & ON_GFLAG_MODERATOR) && user->level == LEVEL_MODERATOR) ||
		    ((data->flags & ON_GFLAG_LEECH) && user->level == LEVEL_LEECH) ||
		    ((data->flags & ON_GFLAG_MUZZLED) && user->muzzled) ||
		    ((data->flags & ON_GFLAG_CLOAKED) && user->cloaked)))
	    return;
    }
    if (data->server && *data->server != '*' &&
	    strcasecmp (data->server, user->server) != 0)
	return;			/* no match */
    send_cmd (data->con, MSG_SERVER_GLOBAL_USER_LIST, "%s %s", user->nick,
	    my_ntoa (user->ip));
}

/* 831 [server] [flags] */
HANDLER (global_user_list)
{
    struct guldata data;

    ASSERT (validate_connection (con));
    (void) len;
    CHECK_USER_CLASS ("global_user_list");
    if (con->user->level < LEVEL_MODERATOR)
    {
	permission_denied (con);
	return;
    }
    data.con = con;
    data.server = next_arg (&pkt);
    data.flags = 0;
    if (pkt)
    {
	while (*pkt)
	{
	    switch (*pkt)
	    {
	    case 'e':
		data.flags |= ON_GFLAG_ELITE;
		break;
	    case 'a':
		data.flags |= ON_GFLAG_ADMIN;
		break;
	    case 'm':
		data.flags |= ON_GFLAG_MODERATOR;
		break;
	    case 'l':
		data.flags |= ON_GFLAG_LEECH;
		break;
	    case 'z':
		data.flags |= ON_GFLAG_MUZZLED;
		break;
	    case 'c':
		data.flags |= ON_GFLAG_CLOAKED;
		break;
	    }
	    pkt++;
	}
    }
    hash_foreach (Users, (hash_callback_t) global_user_list_cb, &data);
    send_cmd (con, tag, "");	/* end of list */
}
