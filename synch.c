/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"
#include "debug.h"

char *Levels[LEVEL_ELITE+1] = {
    "Leech",
    "User",
    "Moderator",
    "Admin",
    "Elite"
};

static void
sync_file (DATUM *info, CONNECTION *con)
{
    ASSERT (validate_connection (con));

    if (info->type == CT_AUDIO)
    send_cmd (con, MSG_CLIENT_ADD_FILE, ":%s \"%s\" %s %d %hu %hu %hu",
	    info->user->nick, info->filename, info->hash, info->size,
	    info->bitrate, info->frequency, info->duration);
    else
	send_cmd (con, MSG_CLIENT_SHARE_FILE, ":%s \"%s\" %d %s %s",
		info->user->nick, info->filename, info->size,
		info->hash, Content_Types[info->type]);
}

static void
sync_user (USER *user, CONNECTION *con)
{
    int i;

    ASSERT (validate_connection (con));
    ASSERT (validate_user (user));

    /* we should never tell a peer server about a user that is behind
       them */
    ASSERT (user->con != con);
    if (user->con == con)
    {
	/* this really shouldnt happen! */
	ASSERT (0);
	return;
    }

    /* send a login message for this user */
    send_cmd (con, MSG_CLIENT_LOGIN, "%s %s %d \"%s\" %d",
	    user->nick, user->pass, user->port, user->clientinfo, user->speed);

    /* send the user's host */
    send_cmd (con, MSG_SERVER_USER_IP, "%s %lu %hu %s", user->nick,
	user->host, user->conport, user->server);

    /* update the user's level */
    if (user->level != LEVEL_USER)
    {
	send_cmd (con, MSG_CLIENT_SETUSERLEVEL, ":%s %s %s",
	    Server_Name, user->nick, Levels[user->level]);
    }

    /* send the channels this user is listening on */
    for (i = 0; i < user->numchannels; i++)
    {
	send_cmd (con, MSG_CLIENT_JOIN, ":%s %s",
		user->nick, user->channels[i]->name);
    }

    /* sync the files for this user */
    hash_foreach (user->files, (hash_callback_t) sync_file, con);
}

void
synch_server (CONNECTION *con)
{
    ASSERT (validate_connection (con));

    log ("synch_server(): syncing");

    /* send our peer server a list of all users we know about */
    hash_foreach (Users, (hash_callback_t) sync_user, con);

    log ("synch_server(): done");
}
