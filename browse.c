/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

typedef struct
{
    short count;
    short max;
    USER *sender;
    USER *user;
}
BROWSE;

static void
browse_callback (DATUM * info, BROWSE * ctx)
{
    /* avoid flooding the client */
    if (ctx->max == 0 || ctx->count < ctx->max)
    {
	send_user (ctx->sender, MSG_SERVER_BROWSE_RESPONSE,
		   "%s \"%s\" %s %d %hu %hu %hu",
		   info->user->nick,
		   info->filename,
#if RESUME
		   info->hash,
#else
		   "00000000000000000000000000000000",
#endif
		   info->size,
		   BitRate[info->bitrate], SampleRate[info->frequency],
		   info->duration);

	ctx->count++;
    }
}

/* 211 [ :<sender> ] <nick> [ <max> ]
   browse a user's files */
HANDLER (browse)
{
    USER *sender, *user;
    BROWSE data;
    char *nick;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &sender))
	return;
    if(!pkt)
    {
	unparsable(con);
	return;
    }
    nick = next_arg (&pkt);
    if(invalid_nick(nick))
    {
	invalid_nick_msg(con);
	return;
    }
    user = hash_lookup (Users, nick);
    if (!user)
    {
	if (ISUSER (con))
	{
	    /* the napster servers send a 210 instead of 404 for this case */
	    send_cmd (con, MSG_SERVER_USER_SIGNOFF, "%s", nick);
	    /* always terminate the list */
	    send_cmd (con, MSG_SERVER_BROWSE_END, "%s", nick);
	}
	return;
    }
    ASSERT (validate_user (user));

    if (ISUSER (user->con))
    {
	if (user->con->uopt->files)
	{
	    data.count = 0;
	    data.user = user;
	    data.sender = sender;
	    data.max = pkt ? atoi (pkt) : 0;
	    if (Max_Browse_Result > 0 && data.max > Max_Browse_Result)
		data.max = Max_Browse_Result;
	    hash_foreach (user->con->uopt->files,
			  (hash_callback_t) browse_callback, &data);
	}

	/* send end of browse list message */
	send_user (sender, MSG_SERVER_BROWSE_END, "%s", user->nick);
    }
    else
    {
	/* relay to the server that this user is connected to */
	send_cmd (user->con, tag, ":%s %s %d", sender->nick, user->nick,
		  pkt ? atoi (pkt) : Max_Browse_Result);
    }
}
