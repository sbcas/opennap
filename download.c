/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#ifndef WIN32
#include <unistd.h>
#else
#include <windows.h>
#endif /* !WIN32 */
#include <stdio.h>
#include <mysql.h>
#include "opennap.h"
#include "debug.h"

extern MYSQL *Db;

/* 203 <nick> <filename> */
/* 500 <nick> <filename> */
/* handle client request for download of a file */
HANDLER (download)
{
    char *fields[2];
    USER *user;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

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
    ASSERT (validate_user (user));

    /* make sure both parties are not firewalled
       -and-
       client is not making a 203 request to a firewalled user (this isn't
       really necessary it seems, but to maintain compatibility with the
       official server, we'll return an error */
    if (user->port == 0 &&
	    (con->user->port == 0 || tag == MSG_CLIENT_DOWNLOAD))
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

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    user = transfer_count_wrapper (con, pkt, MSG_CLIENT_UPLOAD_START);
    if (!user)
	return;
    ASSERT (validate_user (user));
    user->uploads++;
    user->totalup++;
}

/* 221 [ :<user> ] */
HANDLER(upload_end)
{
    USER *user;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    user = transfer_count_wrapper (con, pkt, MSG_CLIENT_UPLOAD_END);
    if (!user)
	return;
    ASSERT (validate_user (user));
    if (user->uploads > 0)
	user->uploads--;
}

/* 218 [ :<user> ] */
HANDLER(download_start)
{
    USER *user;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    user = transfer_count_wrapper (con, pkt, MSG_CLIENT_DOWNLOAD_START);
    if (!user)
	return;
    ASSERT (validate_user (user));
    user->downloads++;
    user->totaldown++;
}

/* 219 [ :<user> ] */
HANDLER(download_end)
{
    USER *user;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    user = transfer_count_wrapper (con, pkt, MSG_CLIENT_DOWNLOAD_END);
    if (!user)
	return;
    ASSERT (validate_user (user));
    if (user->downloads > 0)
	user->downloads--;
}

/* 600 <user> */
/* client is requesting the link speed of <user> */
HANDLER (user_speed)
{
    USER *user;
    (void) tag;
    (void) len;
    CHECK_USER_CLASS("user_speed");
    user = hash_lookup (Users, pkt);
    if(!user)
    {
	/* TODO: what error does the server return here? */
	log("user_speed():no such user %s", pkt);
	return;
    }
    ASSERT (validate_user (user));
    send_cmd (con, MSG_SERVER_USER_SPEED /* 601 */, "%s %d",
	    user->nick, user->speed);
}

/* 626 [ :<nick> ] <user> */
/* client is notifying other party of a failure to connect to their data
   port */
HANDLER (data_port_error)
{
    USER *sender, *user;
    (void) tag;
    (void) len;

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

/* 607 :<sender> <recip> "<filename>" */
HANDLER (upload_request)
{
    char *fields[3];
    USER *recip;

    (void) tag;
    (void) len;

    ASSERT (validate_connection (con));
    CHECK_SERVER_CLASS ("upload_request");
    if (split_line (fields, sizeof (fields) / sizeof (char *), pkt) != 3)
    {
	log ("upload_request(): wrong number of args");
	return;
    }
    if (*fields[0] != ':')
    {
	log ("upload_request(): missing colon (:) prefix in server message");
	return;
    }

    recip = hash_lookup (Users, fields[1]);
    if (!recip)
    {
	log ("upload_request(): unable to find user %s", fields[1]);
	return;
    }
    ASSERT (validate_user (recip));
    if (recip->con)
    {
	/* local user, deliver the message */
	send_cmd (recip->con, MSG_SERVER_UPLOAD_REQUEST /* 607 */, "%s \"%s\"",
		fields[0] + 1, fields[2]);
    }
}

/* 619 [ :<user> ] <nick> <filename> <limit> */
HANDLER (queue_limit)
{
    char *av[3];
    USER *sender, *recip;
    MYSQL_RES	*result;
    MYSQL_ROW	row;
    char path[256];

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &sender) != 0)
	return;
    if (split_line (av, sizeof (av) / sizeof (char *), pkt) < 3)
    {
	log ("queue_limit(): too few arguments");
	if (con->class == CLASS_USER)
	{
	    send_cmd (con, MSG_SERVER_NOSUCH, "too few arguments");
	    return;
	}
	return;
    }
    recip = hash_lookup (Users, av[0]);
    if (!recip)
    {
	log ("queue_limit(): unable to find user %s", av[0]);
	if (con->class == CLASS_USER)
	    nosuchuser (con, av[0]);
	return;
    }
    ASSERT (validate_user (recip));
    if (recip->con)
    {
	/* locally connected, deliver final message */

	/* look up the filesize in the db */
	fudge_path(av[1],path,sizeof(path));
	snprintf (Buf, sizeof (Buf),
		"SELECT size FROM library WHERE owner='%s' && filename='%s'",
		sender->nick, path);
	if (mysql_query (Db, Buf) != 0)
	{
	    sql_error ("queue_limit", Buf);
	    if (con->class == CLASS_USER)
		send_cmd (con, MSG_SERVER_NOSUCH,
			"could not locate \"%s\" in the db", av[1]);
	    return;
	}
	result = mysql_store_result (Db);
	ASSERT (result != 0);
	row = mysql_fetch_row (result);
	ASSERT (row != 0);
	ASSERT (validate_connection (recip->con));
	send_cmd (recip->con, MSG_SERVER_LIMIT, "%s \"%s\" %s %s",
		sender->nick, av[1], row[0], av[2]);
	mysql_free_result (result);
    }
    else if (Num_Servers && con->class == CLASS_USER)
    {
	/* send to peer servers for delivery */
	pass_message_args (con, MSG_CLIENT_LIMIT, ":%s %s \"%s\" %s",
		sender->nick, av[0], av[1], av[2]);
    }
}
