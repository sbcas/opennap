/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License */

#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include "opennap.h"
#include "debug.h"

#define WHOIS_FMT "%s \"%s\" %d \"%s\" \"Active\" %d %d %d %d \"%s\""

/* packet contains: <user> */
HANDLER (whois)
{
    USER *user;
    int i, l;
    char *chanlist;

    ASSERT (VALID (con));
    CHECK_USER_CLASS ("whois");
    user = hash_lookup (Users, pkt);
    if (!user)
    {
	nosuchuser (con, pkt);
	return;
    }

    ASSERT (VALID (user));

    chanlist = STRDUP (" ");

    /* build the channel list this user belongs to */
    for (i = 0; i < user->numchannels; i++)
    {
	l = strlen (chanlist);
	chanlist = REALLOC (chanlist, l + strlen (user->channels[i]->name) + 2);
	strcat (chanlist, user->channels[i]->name);
	strcat (chanlist, " ");
    }

    send_cmd (con, MSG_SERVER_WHOIS_RESPONSE,
	      WHOIS_FMT, user->nick, Levels[user->level],
	      (int) (time (0) - user->connected),
	      chanlist, user->shared, user->downloads, user->uploads,
	      user->speed, user->clientinfo);
    FREE (chanlist);
}
