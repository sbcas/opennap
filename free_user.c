/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#ifdef WIN32
#include <windows.h>
#endif /* WIN32 */
#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

extern MYSQL *Db;

void
free_user (USER * user)
{
    int i;
    HOTLIST *hotlist;

    ASSERT (validate_user (user));

    if (user->con && Num_Servers)
    {
	/* local user, notify peers of this user's departure */
	pass_message_args (user->con, MSG_CLIENT_QUIT, "%s", user->nick);
    }

    /* remove all files for this user from the database */
    if (!SigCaught)
    {
	snprintf (Buf, sizeof (Buf), "DELETE FROM library WHERE owner='%s'",
		user->nick);
	if (mysql_query (Db, Buf) != 0)
	    sql_error ("free_user", Buf);
    }

    /* remove this user from any channels they were on */
    if (user->channels)
    {
	for (i = 0; i < user->numchannels; i++)
	{
	    /* notify locally connected clients in the same channel that
	       this user has parted */
	    part_channel (user->channels[i], user);
	}
	FREE (user->channels);
    }

    Num_Files -= user->shared;
    Num_Gigs -= user->libsize; /* this is in kB */

    /* check the global hotlist for this user to see if anyone wants notice
       of this user's departure */
    hotlist = hash_lookup (Hotlist, user->nick);
    if (hotlist)
    {
	ASSERT (hotlist->numusers > 0);
	for (i = 0; i < hotlist->numusers; i++)
	    send_cmd (hotlist->users[i], MSG_SERVER_USER_SIGNOFF, "%s",
		user->nick);
    }

    FREE (user->nick);
    FREE (user->pass);
    FREE (user->clientinfo);
    FREE (user->server);
    if (user->email)
	FREE (user->email);
    FREE (user);
}
