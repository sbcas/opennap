/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License. */

#include <unistd.h>
#include "opennap.h"

/* 600 <user> */
/* client is requesting the line speed of <user> */
HANDLER (download_ack)
{
    USER *user;

    CHECK_USER_CLASS("download_ack");
    user=hash_lookup(Users,pkt);
    if(!user)
    {
	log("download_ack():no such user %s", pkt);
	return;
    }
    send_cmd(con,601,"%s %d",user->nick,user->speed);
}
