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
#include "opennap.h"
#include "debug.h"

static FILE *MotdFp = 0;

#if 0
/* in-memory copy of the motd */
static char *Motd = 0;
static int MotdLen = 0;
#endif

HANDLER (show_motd)
{
    size_t l;

    (void) tag;
    (void) len;
    (void) pkt;

    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("show_motd");

    /* we print the version info here so that clients can enable features
       only present in this server, but without disturbing the windows
       client */
    send_cmd (con, MSG_SERVER_MOTD, "VERSION %s %s", PACKAGE, VERSION);

    if(MotdFp)
    {
	rewind(MotdFp);

	/* we don't call send_cmd() here because we want to avoid copying the
	   buffer, just use it directly saving time */
	set_tag (Buf, MSG_SERVER_MOTD);
	while (fgets (Buf + 4, sizeof (Buf) - 4, MotdFp))
	{
	    l = strlen (Buf + 4) - 1;
	    set_len (Buf, l);
	    queue_data (con, Buf, 4 + l);
	}
    }
}

void
motd_init(void)
{
    char path[_POSIX_PATH_MAX];

    snprintf (path, sizeof (path), "%s/motd", Config_Dir);
    MotdFp = fopen (path, "r");
    if (!MotdFp)
    {
	if(errno !=ENOENT)
	    logerr("motd_init", path);
	return;
    }
}

void
motd_close(void)
{
    if(MotdFp)
	fclose(MotdFp);
}
