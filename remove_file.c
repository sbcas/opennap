/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"
#include "debug.h"

/* 102 [ :<user> ] <filename> */
HANDLER (remove_file)
{
    USER	*user;
    DATUM	*info;
    int		fsize;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &user) != 0)
	return;
    ASSERT (validate_user (user));

    if (user->shared == 0)
    {
	log ("remove_file(): user %s is not sharing any files", user->nick);
	if (con->class == CLASS_USER)
	    send_cmd (con, MSG_SERVER_NOSUCH, "you aren't sharing any files");
	return;
    }

    /* find the file in the user's list */
    info = hash_lookup (user->files, pkt);
    if (!info)
    {
	log ("remove_file(): user %s is not sharing %s", user->nick, pkt);
	if (con->class == CLASS_USER)
	    send_cmd (con, MSG_SERVER_NOSUCH, "you are not sharing that file");
	return;
    }

    /* adjust the global state information */
    fsize = info->size / 1024; /* kB */
    user->libsize -= fsize;
    Num_Gigs -= fsize;
    ASSERT (Num_Files > 0);
    Num_Files--;
    user->shared--;

    /* this invokes free_datum() indirectly */
    hash_remove (user->files, info->filename);

    /* if a local user, pass this message to our peer servers */
    if (Num_Servers && con->class == CLASS_USER)
	pass_message_args (con, MSG_CLIENT_REMOVE_FILE, ":%s %s",
	    user->nick, pkt);
}
