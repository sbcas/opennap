/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"
#include "debug.h"

/* 203 <nick> "<filename>" */
/* 500 <nick> "<filename>" */
/* handle client request for download of a file */
HANDLER (download)
{
    char	*av[2];
    USER	*user;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    CHECK_USER_CLASS ("download");

    if (split_line (av, sizeof (av) / sizeof (char *), pkt) != 2)
    {
	log ("download(): malformed user request");
	return;
    }

    /* find the user to download from */
    user = hash_lookup (Users, av[0]);
    if (!user)
    {
	nosuchuser (con, av[0]);
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
		    user->port, av[1], user->speed);
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
	    DATUM *info = hash_lookup (user->files, av[1]);
	    if (!info)
	    {
		/* TODO: what error message to return to sender? */
		log ("download(): user %s does not have file %s",
			user->nick, av[1]);
		return;
	    }
	    send_cmd (con, MSG_SERVER_FILE_READY /* 204 */,
		    "%s %lu %d \"%s\" %s %d", user->nick, user->host,
		    user->port, info->filename, info->hash, user->speed);
	    return;
	}
    }

    /* send a message to the requestee */
    log ("download(): REQUEST \"%s\" %s => %s",
	av[1], user->nick, con->user->nick);

    /* if the client holding the file is a local user, send the request
       directly */
    if (user->local)
    {
	send_cmd (user->con, MSG_SERVER_UPLOAD_REQUEST, "%s \"%s\"",
		con->user->nick, av[1]);
    }
    /* otherwise pass it to the peer server for delivery */
    else
    {
	log ("download(): %s is remote, relaying request", user->nick);
	send_cmd (user->con, MSG_SERVER_UPLOAD_REQUEST, ":%s %s \"%s\"",
	    con->user->nick, user->nick, av[1]);
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
    if (user->local)
	send_cmd (user->con, MSG_SERVER_DATA_PORT_ERROR, "%s", sender->nick);
}

/* 607 :<sender> <recip> "<filename>" */
HANDLER (upload_request)
{
    char *av[3];
    USER *recip;

    (void) tag;
    (void) len;

    ASSERT (validate_connection (con));
    CHECK_SERVER_CLASS ("upload_request");
    if (split_line (av, sizeof (av) / sizeof (char *), pkt) != 3)
    {
	log ("upload_request(): wrong number of args");
	return;
    }
    if (*av[0] != ':')
    {
	log ("upload_request(): missing colon (:) prefix in server message");
	return;
    }

    recip = hash_lookup (Users, av[1]);
    if (!recip)
    {
	log ("upload_request(): unable to find user %s", av[1]);
	return;
    }
    ASSERT (validate_user (recip));

    /* if local user, deliver the message */
    if (recip->local)
    {
	send_cmd (recip->con, MSG_SERVER_UPLOAD_REQUEST /* 607 */, "%s \"%s\"",
	    av[0] + 1, av[2]);
    }

    log ("upload_request(): REMOTE REQUEST \"%s\" %s => %s",
	av[2], recip->nick, av[0] + 1);
}

/* 619 [ :<user> ] <nick> <filename> <limit> */
HANDLER (queue_limit)
{
    char *av[3];
    USER *sender, *recip;
    DATUM *info;

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
    if (recip->local)
    {
	ASSERT (validate_connection (recip->con));

	/* look up the filesize in the db */
	info = hash_lookup (sender->files, av[1]);
	if (!info)
	{
	    log ("queue_limit(): user %s does not have file %s",
		    sender->nick, av[1]);
	    if (con->class == CLASS_USER)
		send_cmd (con, MSG_SERVER_NOSUCH,
			"could not locate \"%s\" in the db", av[1]);
	    return;
	}

	send_cmd (recip->con, MSG_SERVER_LIMIT, "%s \"%s\" %d %s",
		sender->nick, info->filename, info->size, av[2]);
    }
    /* send to peer servers for delivery */
    else if (Num_Servers && con->class == CLASS_USER)
    {
	pass_message_args (con, MSG_CLIENT_LIMIT, ":%s %s \"%s\" %s",
		sender->nick, av[0], av[1], av[2]);
    }
}
