/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdlib.h>
#include "opennap.h"

/* 821 [ :sender ] <nick> <server> <port>
 * redirect client to another server
 */
HANDLER (redirect_client)
{
    char *sendernick;
    USER *sender, *user;
    int ac = -1;
    char *av[3];
    int port;

    (void) len;
    if (pop_user_server (con, tag, &pkt, &sendernick, &sender))
	return;

    if (pkt)
	ac = split_line (av, FIELDS (av), pkt);
    if (ac < 3)
    {
	unparsable (con);
	return;
    }

    if (sender->level < LEVEL_ADMIN)
    {
	permission_denied (con);
	return;
    }

    port = atoi (av[2]);
    if (port < 0 || port > 65535)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "invalid port");
	return;
    }

    user = hash_lookup (Users, av[0]);
    if (!user)
    {
	nosuchuser (con);
	return;
    }

    if (ISUSER (user->con))
	send_cmd (user->con, tag, "%s %s", av[1], av[2]);

    notify_mods (CHANGELOG_MODE, "%s redirected %s to %s:%s",
		 sendernick, av[0], av[1], av[2]);

    pass_message_args (con, tag, ":%s %s %s %s", sendernick, av[0], av[1],
		       av[2]);
}

/* 822 [ :sender ] <nick> <server>
 * redirect client to a metaserver
 */
HANDLER (cycle_client)
{
    char *sendernick;
    USER *sender, *user;
    char *nick, *server;

    (void) len;
    if (pop_user_server (con, tag, &pkt, &sendernick, &sender))
	return;

    if (sender->level < LEVEL_ADMIN)
    {
	permission_denied (con);
	return;
    }
    nick = next_arg (&pkt);
    server = next_arg (&pkt);
    if (!nick || !server)
    {
	unparsable (con);
	return;
    }
    user = hash_lookup (Users, nick);
    if (!user)
    {
	nosuchuser (con);
	return;
    }

    if (ISUSER (user->con))
	send_cmd (user->con, tag, "%s", server);

    notify_mods (CHANGELOG_MODE, "%s cycled %s to %s", sendernick,
		 sendernick, nick, server);

    pass_message_args (con, tag, ":%s %s %s", sendernick, nick, server);
}
