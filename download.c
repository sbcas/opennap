/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"
#include "debug.h"

/* 203 [ :<sender> ] <nick> "<filename>" */
/* 500 [ :<sender> ] <nick> "<filename>" */
/* handle client request for download of a file */
HANDLER (download)
{
    char *av[2];
    USER *user, *sender;

    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &sender))
	return;
    if (split_line (av, sizeof (av) / sizeof (char *), pkt) != 2)
    {
	log ("download(): malformed user request");
	return;
    }
    /* find the user to download from */
    user = hash_lookup (Users, av[0]);
    if (!user)
    {
	log ("download(): no such user %s", av[0]);
	send_user (sender, MSG_SERVER_SEND_ERROR, "%s \"%s\"", av[0], av[1]);
	return;
    }
    ASSERT (validate_user (user));

    if (tag == MSG_CLIENT_DOWNLOAD)
    {
	if (user->port == 0)
	{
	    /* uploader is firewalled, send file info so that downloader can
	       send the 500 request */
	    if (user->local)
	    {
		DATUM *info = hash_lookup (user->files, av[1]);

		if (!info)
		{
		    /* TODO: what error message to return to sender? */
		    log ("download(): user %s does not have file %s",
			 user->nick, av[1]);
		    send_user (sender, MSG_SERVER_SEND_ERROR, "%s \"%s\"",
			       user->nick, av[1]);
		}
		else
		{
		    send_user (sender, MSG_SERVER_FILE_READY /* 204 */ ,
			       "%s %u %d \"%s\" %s %d", user->nick,
			       user->host, user->port, info->filename,
			       info->hash, user->speed);
		}
	    }
	    else
	    {
		/* not a local user, we have to relay this request since we
		   dont' have the file information local */
		ASSERT (ISSERVER (user->con));
		send_cmd (user->con, tag, ":%s %s \"%s\"", sender->nick,
			  user->nick, av[1]);
	    }
	    return;
	}
    }
    else
    {
	ASSERT (tag == MSG_CLIENT_DOWNLOAD_FIREWALL);
	if (user->port != 0)
	{
	    /* this user is not firewalled */
	    send_cmd (con, MSG_SERVER_NOSUCH, "%s is not firewalled",
		      user->nick);
	    return;
	}
	if (sender->port == 0)
	{
	    /* error, both clients are firewalled */
	    ASSERT (ISUSER (con));
	    send_cmd (con, MSG_SERVER_FILE_READY /* 204 */ ,
		      "%s %u %d \"%s\" firewallerror %d",
		      user->nick, user->host, user->port, av[1], user->speed);
	    return;
	}
    }

    /* if the client holding the file is a local user, send the request
       directly */
    if (user->local)
    {
	send_cmd (user->con, MSG_SERVER_UPLOAD_REQUEST, "%s \"%s\"",
		  sender->nick, av[1]);
    }
    /* otherwise pass it to the peer servers for delivery */
    else
    {
	/* don't use direct delivery here because the server the client is
	   connected to needs to consult their db and rewrite this messsage */
	send_cmd (user->con, MSG_SERVER_UPLOAD_REQUEST, ":%s %s \"%s\"",
		  sender->nick, user->nick, av[1]);
    }
}

static USER *
transfer_count_wrapper (CONNECTION * con, char *pkt, int numeric)
{
    USER *user;

    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &user))
	return 0;
    /* relay to peer servers */
    pass_message_args (con, numeric, ":%s", user->nick);
    return user;
}

/* 220 [ :<user> ] */
HANDLER (upload_start)
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
HANDLER (upload_end)
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
HANDLER (download_start)
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
HANDLER (download_end)
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
    if (!user)
    {
	log ("user_speed(): no such user %s", pkt);
	send_cmd (con, MSG_SERVER_NOSUCH, "There is no user named  %s", pkt);
	return;
    }
    ASSERT (validate_user (user));
    send_cmd (con, MSG_SERVER_USER_SPEED /* 601 */ , "%s %d",
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
    pass_message_args (con, tag, ":%s %s", sender->nick, user->nick);

    notify_mods
	("Notification from %s: %s (%s) - configured data port %d is unreachable.",
	 sender->nick, user->nick, my_ntoa (user->host), user->port);

    /* if local, notify the target of the error */
    if (user->local)
	send_cmd (user->con, tag, "%s", sender->nick);
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
	send_cmd (recip->con, MSG_SERVER_UPLOAD_REQUEST /* 607 */ ,
		  "%s \"%s\"", av[0] + 1, av[2]);
    }
    else
	pass_message_args (recip->con, MSG_SERVER_UPLOAD_REQUEST,
			   ":%s %s \"%s\"", av[0] + 1, recip->nick, av[2]);
}

/* 619 <nick> <filename> <limit> */
HANDLER (queue_limit)
{
    char *av[3];
    USER *recip;
    DATUM *info;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("queue_limit");
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
	nosuchuser (con, av[0]);
	return;
    }
    ASSERT (validate_user (recip));
    ASSERT (validate_connection (recip->con));

    /* look up the filesize in the db */
    info = hash_lookup (con->user->files, av[1]);
    if (!info)
    {
	log ("queue_limit(): user %s does not have file %s",
	     con->user->nick, av[1]);
	send_cmd (con, MSG_SERVER_NOSUCH,
		  "could not locate \"%s\" in the db", av[1]);
	return;
    }

    /* deliver to user even if remote */
    send_user (recip, MSG_SERVER_LIMIT, "%s \"%s\" %d %s",
	       con->user->nick, info->filename, info->size, av[2]);
}
