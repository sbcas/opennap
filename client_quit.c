/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"
#include "debug.h"

/* handle notification that a user has quit */
/* packet contains just <user> */
HANDLER (client_quit)
{
    USER *user;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (con->class != CLASS_SERVER)
    {
	/* we should only get this message from other servers */
	log ("client_quit(): only SERVER class may send a quit message");
	return;
    }
    user = hash_lookup (Users, pkt);
    if (!user)
    {
	log ("client_quit(): can't find user %s", pkt);
	return;
    }
    ASSERT (validate_user (user));
    ASSERT (user->con == 0);	/* we should never get this message for a
				   local user */
    hash_remove (Users, user->nick);
}
