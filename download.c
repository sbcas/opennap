/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <string.h>
#include "opennap.h"
#include "debug.h"

/* 203 [ :<sender> ] <nick> "<filename>" */
/* 500 [ :<sender> ] <nick> "<filename>" */
/* handle client request for download of a file */
HANDLER (download)
{
    char *av[2];
    USER *user, *sender;
    DATUM *info = 0;

    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &sender))
	return;
    if (split_line (av, sizeof (av) / sizeof (char *), pkt) < 2)
    {
	unparsable (con);
	return;
    }
    /* find the user to download from */
    user = hash_lookup (Users, av[0]);
    if (!user)
    {
	send_user (sender, MSG_SERVER_SEND_ERROR, "%s \"%s\"", av[0], av[1]);
	return;
    }

    if (ISUSER (user->con))
    {
	if (is_ignoring (user->con->uopt->ignore, sender->nick))
	{
	    send_user (sender, MSG_SERVER_NOSUCH, "%s is ignoring you",
		       user->nick);
	    return;
	}

	/* check to make sure the user is actually sharing this file */
	info = hash_lookup (user->con->uopt->files, av[1]);
	if (!info)
	{
	    send_user (sender, MSG_SERVER_SEND_ERROR, "%s \"%s\"",
		       user->nick, av[1]);
	    return;
	}
    }

    if (tag == MSG_CLIENT_DOWNLOAD)
    {
	if (user->port == 0)
	{
	    /* uploader is firewalled, send file info so that downloader can
	       send the 500 request */
	    if (ISUSER (user->con))
	    {
		ASSERT (info != 0);
		send_user (sender, MSG_SERVER_FILE_READY /* 204 */ ,
			   "%s %u %d \"%s\" %s %d", user->nick,
			   user->ip, user->port, av[1],
#if RESUME
			   info->hash,
#else
			   "00000000000000000000000000000000",
#endif
			   user->speed);
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
		      user->nick, user->ip, user->port, av[1], user->speed);
	    return;
	}
    }

    /* if the client holding the file is a local user, send the request
       directly */
    if (ISUSER (user->con))
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
	nosuchuser (con);
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
	nosuchuser (con);
	return;
    }
    ASSERT (validate_user (user));

    /* we pass this message to all servers so the mods can see it */
    pass_message_args (con, tag, ":%s %s", sender->nick, user->nick);

    notify_mods
	(PORTLOG_MODE,
	 "Notification from %s: %s (%s) - configured data port %d is unreachable.",
	 sender->nick, user->nick, my_ntoa (user->ip), user->port);

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
	nosuchuser (con);
	return;
    }
    ASSERT (validate_user (recip));

    /* if local user, deliver the message */
    if (ISUSER (recip->con))
    {
	/* make sure the user is actually sharing this file */
	DATUM *info = hash_lookup (recip->con->uopt->files, av[2]);

	if (!info)
	{
	    log ("upload_request(): %s is not sharing %s", recip->nick,
		 av[2]);
	    return;
	}
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
    int ac;
    USER *recip;
    DATUM *info;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("queue_limit");
    ac = split_line (av, sizeof (av) / sizeof (char *), pkt);

    if (ac != 3)
    {
	log ("queue_limit(): wrong number of parameters");
	print_args (ac, av);
	unparsable (con);
	return;
    }
    recip = hash_lookup (Users, av[0]);
    if (!recip)
    {
	nosuchuser (con);
	return;
    }
    ASSERT (validate_user (recip));
    ASSERT (validate_connection (recip->con));

    /* look up the filesize in the db */
    info = hash_lookup (con->uopt->files, av[1]);
    if (!info)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "Not sharing that file");
	return;
    }

    /* deliver to user even if remote */
    send_user (recip, MSG_SERVER_LIMIT, "%s \"%s\" %d %s",
	       con->user->nick, av[1], info->size, av[2]);
}
