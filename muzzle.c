/* Copyright (C) 2000 drscholl@sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <stdlib.h>
#include <time.h>
#include "opennap.h"
#include "debug.h"

/* [ :<nick> ] <user-to-muzzle> <time> */
void
muzzle (CONNECTION * con, char *pkt)
{
    USER *user;
    char *fields[2];

    ASSERT (VALID (con));

    if (pop_user (con, &pkt, &user) != 0)
	return;

    ASSERT (VALID (user));

    if (! HAS_PRIVILEGE (user))
    {
	log ("muzzle(): %s has no privilege");
	return;
    }

    if (split_line (fields, sizeof (fields) / sizeof (char *), pkt) != 2)
    {
	log ("muzzle(): malformed client request");
	return;
    }

    /* find the user to be muzzled */
    user = hash_lookup (Users, fields[0]);
    if (!user)
    {
	if (con->class == CLASS_USER)
	    nosuchuser (con, fields[0]);
	else
	    log ("muzzle(): can't locate user %s", fields[0]);
	return;
    }
    ASSERT (VALID (user));

    /* set the time until which the user is muzzled */
    user->muzzled = time (0) + atoi (fields[1]);

    if (con->class == CLASS_USER && Num_Servers)
    {
	ASSERT (VALID (con->user));
	pass_message_args (con, MSG_CLIENT_MUZZLE, ":%s %s %s", con->user->nick,
		user->nick, fields[1]);
    }
}
