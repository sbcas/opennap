/* Copyright (C) 1999 drscholl@hotmail.com
   This is free software distributed under the terms of the
   GNU Public License */

#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include "opennap.h"
#include "debug.h"

static const char *
level_name (int flag)
{
    if (flag & FLAG_ADMIN)
	return "Admin";
    if (flag & FLAG_MODERATOR)
	return "Moderator";
    return "User";
}

#define WHOIS_FMT "%s \"%s\" %d \"%s\" \"Active\" %d %d %d %d \"%s\""

/* <user> */
void
whois (CONNECTION * con, char *pkt)
{
    USER *user;
    int i, l;
    char *chanlist;

    ASSERT (VALID (con));
    if (con->class != CLASS_USER)
    {
	log ("whois(): only USER class may execute this command");
	return;
    }

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
	      WHOIS_FMT, user->nick, level_name (user->flags),
	      (int) (time (0) - user->connected),
	      chanlist, user->shared, user->downloads, user->uploads,
	      user->speed, user->clientinfo);
    FREE (chanlist);
}
