/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"
#include "debug.h"

/* 608 <recip> "<filename>" */
/* a client sends this message when another user has requested a file from
   them and they are accepting the connection.  this should be a
   response to the 607 upload request */
HANDLER (upload_ok)
{
    char *av[2];
    USER *recip;
    DATUM *info = 0;

    (void) tag;
    (void) len;
    CHECK_USER_CLASS("upload_ok");
    ASSERT (validate_connection (con));
    if (split_line (av, sizeof (av) / sizeof (char *), pkt) != 2)
    {
	log ("upload_ok(): malformed message from %s", con->user->nick);
	return;
    }
    recip = hash_lookup (Users, av[0]);
    if (!recip)
    {
	log ("upload_ok(): no such user %s", av[0]);
	return;
    }
    /* pull the hash from the data base */
    info = hash_lookup (con->user->files, av[1]);
    if (!info)
    {
	log ("upload_ok(): user %s does not have file %s",
		con->user->nick, av[1]);
	return;
    }
    log ("upload_ok(): ACK \"%s\" %s => %s", av[1], con->user->nick,
	    recip->nick);
    if (con->user->port == 0)
    {
	/* firewalled user, give the info back to the uploader */
	send_cmd (con, MSG_SERVER_UPLOAD_FIREWALL /* 501 */ ,
		"%s %lu %d \"%s\" %s %d",
		recip->nick, recip->host, recip->port, av[1], info->hash,
		recip->speed);
    }
    else
	send_user (recip, MSG_SERVER_FILE_READY, "%s %u %d \"%s\" %s %d",
		con->user->nick, con->user->host, con->user->port, av[1],
		info->hash,
		con->user->speed);
}
