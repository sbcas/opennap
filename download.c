/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "opennap.h"
#include "debug.h"

/* 203 <nick> <filename> */
/* 500 <nick> <filename> */
/* handle client request for download of a file */
HANDLER (download)
{
    char *fields[2];
    USER *user;
    short msg;

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

    /* peek at the message type since we use this for both 203 and 500 */
    memcpy (&msg, con->recvhdr + 2, 2);
#if WORDS_BIGENDIAN
    msg = BSWAP16 (msg);
#endif

    /* make sure both parties are not firewalled
       -and-
       client is not making a 203 request to a firewalled user (this isn't
       really necessary it seems, but to maintain compatibility with the
       official server, we'll return an error */
    if (user->port == 0 &&
	    (con->user->port == 0 || msg == MSG_CLIENT_DOWNLOAD))
    {
	send_cmd (con, MSG_SERVER_FILE_READY,
		"%s %lu %d \"%s\" firewallerror 0", user->nick, user->host,
		user->port, fields[1]);
	return;
    }

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

static USER *
transfer_count_wrapper (CONNECTION *con, char *pkt, int numeric)
{
    USER *user;

    ASSERT (validate_connection (con));
    if (con->class == CLASS_USER)
    {
	user = con->user;
	if (Num_Servers)
	    pass_message_args (con, numeric, ":%s", user->nick);
    }
    else if ((user = hash_lookup (Users, pkt + 1)) == 0)
    {
	log ("transfer_count_wrapper(): could not find %s", pkt + 1);
	return 0;
    }
    return user;
}

/* 220 [ :<user> ] */
HANDLER(upload_start)
{
    USER *user;

    ASSERT (validate_connection (con));
    user = transfer_count_wrapper (con, pkt, MSG_CLIENT_UPLOAD_START);
    ASSERT (validate_user (user));
    user->uploads++;
    user->totalup++;
}

/* 221 [ :<user> ] */
HANDLER(upload_end)
{
    USER *user;

    ASSERT (validate_connection (con));
    user = transfer_count_wrapper (con, pkt, MSG_CLIENT_UPLOAD_END);
    ASSERT (validate_user (user));
    user->uploads--;
}

/* 218 [ :<user> ] */
HANDLER(download_start)
{
    USER *user;

    ASSERT (validate_connection (con));
    user = transfer_count_wrapper (con, pkt, MSG_CLIENT_DOWNLOAD_START);
    ASSERT (validate_user (user));
    user->downloads++;
    user->totaldown++;
}

/* 219 [ :<user> ] */
HANDLER(download_end)
{
    USER *user;

    ASSERT (validate_connection (con));
    user = transfer_count_wrapper (con, pkt, MSG_CLIENT_DOWNLOAD_END);
    ASSERT (validate_user (user));
    user->downloads--;
}

/* 600 <user> */
/* client is requesting the link speed of <user> */
HANDLER(user_speed)
{
    USER *user;
    CHECK_USER_CLASS("user_speed");
    user=hash_lookup(Users,pkt);
    if(!user)
    {
	/* TODO: what error does the server return here? */
	log("user_speed():no such user %s", pkt);
	return;
    }
    send_cmd(con,MSG_SERVER_USER_SPEED /* 601 */, "%s %d",
	    user->nick,user->speed);
}

static char *
my_ntoa (unsigned long ip)
{
    struct in_addr a;
    memset(&a,0,sizeof(a));
    a.s_addr = ip;
    return (inet_ntoa (a));
}

/* 626 [ :<nick> ] <user> */
/* client is notifying other party of a failure to connect to their data
   port */
HANDLER (data_port_error)
{
    USER *sender, *user;

    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &sender) != 0)
	return;
    ASSERT (validate_user (sender));
    user = hash_lookup (Users, pkt);
    if (!user)
    {
	log ("data_port_error(): no such user %s", pkt);
	return;
    }
    ASSERT (validate_user (user));

    /* we pass this message to all servers so the mods can see it */
    if (con->class == CLASS_USER)
    {
	pass_message_args (con, MSG_SERVER_DATA_PORT_ERROR, ":%s %s",
		sender->nick, user->nick);
    }

    notify_mods ("Notification from %s: %s (%s) - configured data port %d is unreachable.",
	    sender->nick, user->nick, my_ntoa (user->host), user->port);

    /* if local, notify the target of the error */
    if (user->con)
	send_cmd (user->con, MSG_SERVER_DATA_PORT_ERROR, "%s", sender->nick);
}
