/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <unistd.h>
#include <stdio.h>
#include "opennap.h"
#include "debug.h"

/* 203 <nick> <filename> */
/* handle client request for download of a file */
HANDLER (download)
{
    char *fields[2];
    USER *user;

    ASSERT (VALID (con));

    CHECK_USER_CLASS ("download");

    if (split_line (fields, sizeof (fields) / sizeof (char *), pkt) != 2)
    {
	log ("download(): malformed user request");
	return;
    }
    user = hash_lookup (Users, fields[0]);
    if (!user)
    {
	nosuchuser (con, fields[0]);
	return;
    }
    ASSERT (VALID (user));

    /* send a message to the requestee */
    log ("download(): sending upload request to %s", user->nick);

    /* if the requestee is a local user, send the request directly */
    if (user->con)
    {
	send_cmd (user->con, MSG_SERVER_UPLOAD_REQUEST, "%s \"%s\"",
		con->user->nick, fields[1]);
    }
    else
    {
	/* otherwise pass it to our peer servers for delivery */
	send_cmd (user->serv, MSG_SERVER_UPLOAD_REQUEST, ":%s %s \"%s\"",
		con->user->nick, fields[0], fields[1]);
    }
}

HANDLER(upload_start)
{
    (void)pkt;
    ASSERT(VALID(con));
    CHECK_USER_CLASS("upload_start");
    con->user->uploads++;
}

HANDLER(upload_end)
{
    (void)pkt;
    ASSERT(VALID(con));
    CHECK_USER_CLASS("upload_end");
    con->user->uploads--;
}

HANDLER(download_start)
{
    (void)pkt;
    ASSERT(VALID(con));
    CHECK_USER_CLASS("download_start");
    con->user->downloads++;
}

HANDLER(download_end)
{
    (void)pkt;
    ASSERT(VALID(con));
    CHECK_USER_CLASS("download_end");
    con->user->downloads--;
}
