/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdio.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include <string.h>
#include "opennap.h"
#include "debug.h"

/* [ :<sender> ] <channel> <text> */
/*  public message to a channel */
HANDLER (public)
{
    CHANNEL *chan;
    USER *chanUser, *sender;
    LIST *list;
    char *ptr;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    /* save the starting position of the pkt */
    ptr = pkt;
    if (pop_user (con, &pkt, &sender))
	return;
    if (sender->muzzled)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "You are muzzled.");
	return;
    }

    /* protect against DoS attack against the windows napster client */
    if (len - (pkt - ptr) > 180)
    {
	pkt[180] = 0;	/* crop the message */
	log ("public(): cropped %d byte message from user %s", len, sender->nick);
    }

    /* can't use split line here because the text field is considered all
       one item */
    /* extract the channel name. NOTE: we don't use next_arg() here because
       it will strip leading space from the text being sent */
    ptr = next_arg_noskip (&pkt);
    if (!pkt)
    {
	unparsable(con);
	return;
    }

    /* find the channel this message is going to. look the user's joined
     channels since this should be faster than lookup in the hash table */
    if(!(chan=find_channel(sender->channels,ptr)))
    {
	if(ISUSER(con))
	    send_cmd(con,MSG_SERVER_NOSUCH,"You are not a member of that channel");
	return;
    }

    /* relay this message to peer servers */
    pass_message_args (con, tag, ":%s %s %s", sender->nick, chan->name, pkt);

    /* send this message to everyone in the channel */
    for (list = chan->users; list; list = list->next)
    {
	chanUser = list->data;
	if (ISUSER (chanUser->con))
	{
	    send_cmd(chanUser->con,tag,"%s %s %s", chan->name,
		    (!sender->cloaked || chanUser->level > LEVEL_USER)?sender->nick:"Operator",
		    pkt);
	}
    }
}

/* 824 [ :<user> ] <channel> "<text>" */
HANDLER (emote)
{
    USER *user, *chanUser;
    CHANNEL *chan;
    char *ptr, *av[2];
    LIST *list;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    ptr=pkt;	/* save initial location */
    if (pop_user (con, &pkt, &user) != 0)
	return;
    if (user->muzzled)
    {
	if (ISUSER (con))
	    send_cmd (con, MSG_SERVER_NOSUCH, "You are muzzled");
	return;
    }

    /* protect against DoS attack against the windows napster client */
    if (len - (pkt - ptr) > 180)
    {
	/* crop message */
	pkt[179]='"';
	pkt[180]=0;
	log ("emote(): cropped %d byte message from user %s", len, user->nick);
    }

    if (split_line (av, sizeof (av) / sizeof (char *), pkt) < 2)
    {
	unparsable(con);
	return;
    }

    /* find the channel this message is going to. look the user's joined
     channels since this should be faster than lookup in the hash table */
    if(!(chan=find_channel(user->channels,av[0])))
    {
	if(ISUSER(con))
	    send_cmd(con,MSG_SERVER_NOSUCH,"You are not a member of that channel");
	return;
    }

    /* relay to peer servers */
    pass_message_args (con, tag, ":%s %s \"%s\"", user->nick, chan->name, av[1]);

    /* send this message to all channel members */
    for (list = chan->users; list; list = list->next)
    {
	chanUser = list->data;
	if (ISUSER(chanUser->con))
	{
	    send_cmd(chanUser->con,tag,"%s %s \"%s\"", chan->name,
		    (!user->cloaked || chanUser->level > LEVEL_MODERATOR)?user->nick:"Operator",
		    av[1]);
	}
    }
}
