/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdlib.h>
#include <string.h>
#include <limits.h>
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
		   info->user->nick, info->filename,
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
    if (!pkt)
    {
	unparsable (con);
	return;
    }
    nick = next_arg (&pkt);
    if (invalid_nick (nick))
    {
	invalid_nick_msg (con);
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

static void
create_file_list (DATUM * d, LIST ** p)
{
    DATUM *f;

    while (*p)
    {
	f = (*p)->data;
	if (strcasecmp (d->filename, f->filename) <= 0)
	{
	    LIST *n = CALLOC (1, sizeof (LIST));

	    n->data = d;
	    n->next = *p;
	    *p = n;
	    return;
	}
	p = &(*p)->next;
    }
    *p = CALLOC (1, sizeof (LIST));
    (*p)->data = d;
}

static char *
last_slash (char *s)
{
    /* const */ char *p;

    for (;;)
    {
	p = strpbrk (s + 1, "/\\");
	if (!p)
	    return s;
	s = p;
    }
}

static char *
dirname (char *d, int dsize, /* const */ char *s)
{
    char *p;

    strncpy (d, s, dsize - 1);
    d[dsize - 1] = 0;
    p = last_slash (d);
    *p = 0;
    return d;
}

static char *
basename (char *d, int dsize, /* const */ char *s)
{
    s = last_slash (s);
    strncpy (d, s + 1, dsize - 1);
    d[dsize - 1] = 0;
    return d;
}

/* 10301 [ :<sender> ] <nick>
   new browse requst */
HANDLER (browse_new)
{
    USER *sender, *user;
    char *nick;
    int results = Max_Browse_Result;

    ASSERT (validate_connection (con));
    if (pop_user (con, &pkt, &sender))
	return;
    nick = next_arg (&pkt);
    if (!nick)
    {
	unparsable (con);
	return;
    }
    user = hash_lookup (Users, nick);
    if (!user)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "browse failed: no such user");
	send_user(sender,tag,"%s",nick);	/* always terminate */
	return;
    }
    if(pkt)
    {
	results = atoi (pkt);
	if(results>Max_Browse_Result)
	    results=Max_Browse_Result;
    }
    if (ISUSER (user->con))
    {
	if (user->con->uopt->files)
	{
	    LIST *list = 0, *tmpList;
	    char dir[_POSIX_PATH_MAX];
	    char path[_POSIX_PATH_MAX];
	    char base[_POSIX_PATH_MAX];
	    char *rsp = 0;
	    int count = 0;

	    hash_foreach (user->con->uopt->files,
			  (hash_callback_t) create_file_list, &list);
	    dir[0] = 0;
	    for (tmpList = list; tmpList && results;
		    tmpList = tmpList->next, results--)
	    {
		DATUM *d = tmpList->data;

		dirname (path, sizeof (path), d->filename);
		basename (base, sizeof (base), d->filename);
		if (count < 5 && dir[0] && !strcasecmp (dir, path))
		{
		    /* same directory as previous result, append */
		    rsp = append_string (rsp, " \"%s\" %s %d %d %d %d", base,
#if RESUME
					 d->md5,
#else
					 "0",
#endif
					 d->size,
					 BitRate[d->bitrate],
					 SampleRate[d->frequency],
					 d->duration);
		    if(!rsp)
			break;
		    count++;
		}
		else
		{
		    /* new directory */
		    strcpy (dir, path);
		    if (rsp)
		    {
			/* send off the previous buffer command */
			send_user (sender, MSG_SERVER_BROWSE_RESULT_NEW, "%s",
				   rsp);
			FREE (rsp);
		    }
		    rsp = append_string (0, "%s \"%s\" \"%s\" %s %d %d %d %d",
					 user->nick, dir, base,
#if RESUME
					 d->md5,
#else
					 "0",
#endif
					 d->size,
					 BitRate[d->bitrate],
					 SampleRate[d->frequency],
					 d->duration);
		    if (!rsp)
			break;
		    count = 0;
		}
	    }
	    list_free (list, 0);

	    if (rsp)
	    {
		send_user (sender, MSG_SERVER_BROWSE_RESULT_NEW, "%s", rsp);
		FREE (rsp);
	    }
	}
	/*terminate the list */
	send_user (sender, tag, "%s", user->nick);
    }
    else
    {
	/* relay the request to the server where this user is connected */
	send_cmd (user->con, tag, ":%s %s %d", sender->nick, user->nick,
		results);
    }
}
