/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include "opennap.h"
#include "debug.h"

typedef struct {
    int count;
    CONNECTION *con;
    USER *user;
} BROWSE;

static void
browse_callback (DATUM *info, BROWSE *ctx)
{
    /* avoid flooding the client */
    if (Max_Browse_Result == 0 || ctx->count < Max_Browse_Result)
    {
	send_cmd (ctx->con, MSG_SERVER_BROWSE_RESPONSE,
	    "%s \"%s\" %s %d %hu %hu %hu",
	    info->user->nick,
	    info->filename,
	    info->hash,
	    info->size,
	    info->bitrate,
	    info->frequency,
	    info->duration);

	ctx->count++;
    }
}

HANDLER (browse)
{
    USER *user;
    BROWSE data;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS("browse");
    user = hash_lookup (Users, pkt);
    if (!user)
    {
	nosuchuser (con, pkt);
	return;
    }
    ASSERT (validate_user (user));

    if(user->files)
    {
	data.count = 0;
	data.con = con;
	data.user = user;
	hash_foreach (user->files, (hash_callback_t) browse_callback, &data);
    }

    /* send end of browse list message */
    send_cmd (con, MSG_SERVER_BROWSE_END, "%s", user->nick);
}
