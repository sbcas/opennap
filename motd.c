/* Copyright (C) drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#ifndef WIN32
#include <unistd.h>
#endif
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

/* in-memory copy of the motd */
static char *Motd = 0;
static int MotdLen = 0;

/* ???
   display the server motd */
HANDLER (show_motd)
{
    (void) tag;
    (void) len;
    (void) pkt;

    ASSERT (validate_connection (con));

    /* we print the version info here so that clients can enable features
       only present in this server, but without disturbing the windows
       client */
    send_cmd (con, MSG_SERVER_MOTD, "VERSION %s %s", PACKAGE, VERSION);

    /* motd_init() preformats the entire motd */
    queue_data(con,Motd,MotdLen);
}

void
motd_init(void)
{
    char path[_POSIX_PATH_MAX];
    FILE *fp;
    int len;

    snprintf (path, sizeof (path), "%s/motd", Config_Dir);
    fp = fopen (path, "r");
    if (!fp)
    {
	if(errno !=ENOENT)
	    logerr("motd_init", path);
	return;
    }
    /* preformat the motd so it can be bulk dumped to the client */
    while(fgets(Buf,sizeof(Buf)-1,fp))
    {
	len=strlen(Buf);
	if(Buf[len-1]=='\n')
	    len--;
	if(safe_realloc((void**)&Motd, MotdLen + len + 4))
	    break;
	set_tag(&Motd[MotdLen], MSG_SERVER_MOTD);
	set_len(&Motd[MotdLen], len);
	MotdLen+=4;
	memcpy(Motd+MotdLen,Buf,len);
	MotdLen+=len;
    }
    fclose(fp);
    log("motd_init(): motd is %d bytes", MotdLen);
}

void
motd_close(void)
{
    if(Motd)
    {
	FREE(Motd);
	Motd=0;
	MotdLen=0;
    }
    ASSERT(MotdLen==0);
}
