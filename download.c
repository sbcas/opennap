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

/* 203 <nick> "<filename>" */
/* 500 <nick> "<filename>" */
/* handle client request for download of a file */
HANDLER (download)
{
    char	*fields[2];
    USER	*user;
    MYSQL_RES	*result;
    MYSQL_ROW	row;
    char	path[256];

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    CHECK_USER_CLASS ("download");

    if (split_line (fields, sizeof (fields) / sizeof (char *), pkt) != 2)
    {
	log ("download(): malformed user request");
	return;
    }

    /* find the user to download from */
    user = hash_lookup (Users, fields[0]);
    if (!user)
    {
	nosuchuser (con, fields[0]);
	return;
    }
    ASSERT (validate_user (user));

    if (tag == MSG_CLIENT_DOWNLOAD_FIREWALL /* 500 */)
    {
	if (user->port != 0)
	{
	    /* this user is not firewalled */
	    send_cmd (con, MSG_SERVER_NOSUCH, "%s is not firewalled",
		    user->nick);
	    return;
	}
	if (con->user->port == 0)
	{
	    /* error, both clients are firewalled */
	    send_cmd (con, MSG_SERVER_FILE_READY /* 204 */,
		    "%s %lu %d \"%s\" firewallerror %d", user->nick, user->host,
		    user->port, fields[1], user->speed);
	    return;
	}
    }
    else
    {
	ASSERT (tag == MSG_CLIENT_DOWNLOAD);
	if (user->port == 0)
	{
	    /* uploader is firewalled, send file info so that downloader can
	       send the 500 request */
	    fudge_path (fields[1], path, sizeof (path));
	    snprintf (Buf, sizeof (Buf),
		    "SELECT md5 FROM library WHERE owner='%s' && filename='%s'",
		    user->nick, path);
	    if (mysql_query (Db, Buf))
	    {
		sql_error ("download", Buf);
		return;
	    }
	    result = mysql_store_result (Db);
	    if (!result)
	    {
		log ("download(): mysql_store_result() returned NULL");
		return;
	    }
	    if (mysql_num_rows (result) != 1)
	    {
		log ("download(): expected 1 row returned from SQL query");
		mysql_free_result (result);
		return;
	    }
	    row = mysql_fetch_row (result);
	    if (!row)
	    {
		log ("download(): mysql_fetch_row() returned NULL");
		mysql_free_result (result);
		return;
	    }
	    send_cmd (con, MSG_SERVER_FILE_READY /* 204 */,
		    "%s %lu %d \"%s\" %s %d", user->nick, user->host,
		    user->port, fields[1], row[0], user->speed);
	    mysql_free_result (result);
	    return;
	}
    }

    /* send a message to the requestee */
    log ("download(): REQUEST \"%s\" %s => %s",
	fields[1], user->nick, con->user->nick);

    /* if the client holding the file is a local user, send the request
       directly */
    if (user->con)
    {
	send_cmd (user->con, MSG_SERVER_UPLOAD_REQUEST, "%s \"%s\"",
		con->user->nick, fields[1]);
    }
    /* otherwise pass it to the peer server for delivery */
    else
    {
	log ("download(): %s is remote, relaying request", user->nick);
	send_cmd (user->serv, MSG_SERVER_UPLOAD_REQUEST, ":%s %s \"%s\"",
	    con->user->nick, user->nick, fields[1]);
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

    CHECK_USER_CLASS ("user_speed");
    user = hash_lookup (Users, pkt);
    if(!user)
    {
	/* TODO: what error does the server return here? */
	log ("user_speed(): no such user %s", pkt);
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
    if (con->class == CLASS_USER && Num_Servers)
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

    /* if local user, deliver the message */
    if (recip->con)
    {
	send_cmd (recip->con, MSG_SERVER_UPLOAD_REQUEST /* 607 */, "%s \"%s\"",
	    fields[0] + 1, fields[2]);
    }

    log ("upload_request(): REMOTE REQUEST \"%s\" %s => %s",
	fields[2], recip->nick, fields[0] + 1);
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
    /* locally connected, deliver final message */
    if (recip->con)
    {
	/* look up the filesize in the db */
	fudge_path (av[1], path, sizeof (path));
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
	if (mysql_num_rows (result) > 0)
	{
	    ASSERT (validate_connection (recip->con));
	    send_cmd (recip->con, MSG_SERVER_LIMIT, "%s \"%s\" %s %s",
		    sender->nick, av[1], row[0], av[2]);
	}
	else
	    log ("queue_limit(): mysql_num_rows returned 0");
	mysql_free_result (result);

    }
    /* send to peer servers for delivery */
    else if (Num_Servers && con->class == CLASS_USER)
    {
	pass_message_args (con, MSG_CLIENT_LIMIT, ":%s %s \"%s\" %s",
		sender->nick, av[0], av[1], av[2]);
    }
}
