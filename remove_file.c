/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"
#include "debug.h"

/* 102 <filename> */
HANDLER (remove_file)
{
    USER	*user;
    DATUM	*info;
    int		fsize;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS("remove_file");
    user=con->user;
    if (user->shared == 0)
    {
	log ("remove_file(): user %s is not sharing any files", user->nick);
	send_cmd (con, MSG_SERVER_NOSUCH, "you aren't sharing any files");
	return;
    }

    /* find the file in the user's list */
    info = hash_lookup (user->files, pkt);
    if (!info)
    {
	log ("remove_file(): user %s is not sharing %s", user->nick, pkt);
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
}
