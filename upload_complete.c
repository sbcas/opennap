/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License. */

#include <unistd.h>
#include <stdio.h>
#include "opennap.h"
#include "debug.h"

/* client notified us that its upload is complete */
/* <nick> <filename> */
HANDLER (upload_complete)
{
    char *field[2];
    USER *user;

    CHECK_USER_CLASS ("upload_complete");

    if (split_line (field, sizeof (field) / sizeof (char *), pkt) != 2)
    {
	log ("upload_complete(): malformed message from %s@%s",
	     con->user->nick, con->host);
	return;
    }

    user = hash_lookup (Users, field[0]);
    if (!user)
    {
	log ("upload_complete(): no such user %s", field[0]);
	return;
    }
    user->downloads--;
    con->user->uploads--;

    /* ack the uploader */
    send_cmd (con, MSG_SERVER_UPLOAD_COMPLETE_ACK, "%s %d", user->nick,
	user->speed);

    /* ack the downloader */
    if (user->con)
    {
	/* local user */
	send_cmd (user->con, MSG_SERVER_UPLOAD_COMPLETE_ACK, "%s %d",
	    con->user->nick, con->user->speed);
    }
    else
    {
	/* remote user. we don't use pass_message_args() here because we
	known which server the user is behind */
	send_cmd (user->serv, MSG_SERVER_UPLOAD_COMPLETE_ACK,
	    ":%s %s %d", con->user->nick, user->nick, con->user->speed);
    }
}
