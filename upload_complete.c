/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"
#include "debug.h"

/* 608 [ :<sender> ] <recip> <filename> */
/* a client sends this message when another user has requested a file from
   them and they are accepting the connection.  this should be a
   response to the 607 upload request */
HANDLER (upload_ok)
{
    char *av[2];
    USER *sender, *recip;
    DATUM *info = 0;

    (void) tag;
    (void) len;

    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &sender) != 0)
	return;

    if (split_line (av, sizeof (av) / sizeof (char *), pkt) != 2)
    {
	log ("upload_ok(): malformed message from %s", sender->nick);
	return;
    }

    recip = hash_lookup (Users, av[0]);
    if (!recip)
    {
	log ("upload_ok(): no such user %s", av[0]);
	return;
    }

    if (sender->port == 0 || recip->con)
    {
	/* pull the hash from the data base */
	info = hash_lookup (sender->files, av[1]);
	if (!info)
	{
	    log ("upload_ok(): user %s does not have file %s",
		    sender->nick, av[1]);
	    return;
	}
    }

    log ("upload_ok(): ACK \"%s\" %s => %s", av[1], sender->nick,
	recip->nick);

    if (sender->port == 0)
    {
	/* firewalled user */
	ASSERT (con->class == CLASS_USER);
	send_cmd (con, MSG_SERVER_UPLOAD_FIREWALL /* 501 */ ,
		  "%s %lu %d \"%s\" %s %d",
		  recip->nick, recip->host, recip->port, av[1], info->hash,
		  recip->speed);
    }
    else if (recip->con)
    {
	/* local connection */
	send_cmd (recip->con, MSG_SERVER_FILE_READY /* 204 */ ,
		  "%s %lu %d \"%s\" %s %d", sender->nick, sender->host,
		  sender->port, av[1], info->hash, sender->speed);
    }
    else if (con->class == CLASS_USER)
    {
	/* send this message to the server the recip is on */
	log ("upload_ok(): %s is remote, relaying message", recip->nick);
	ASSERT (recip->serv != 0);
	send_cmd (recip->serv, MSG_CLIENT_UPLOAD_OK, ":%s %s \"%s\"",
		  sender->nick, recip->nick, av[1]);
    }
}
