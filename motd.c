/* Copyright (C) drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "opennap.h"
#include "debug.h"

void
show_motd (CONNECTION * con)
{
    FILE *f;
    size_t l;

    ASSERT (validate_connection (con));
    /* we print the version info here so that clients can enable features
       only present in this server, but without disturbing the windows
       client */
    send_cmd (con, MSG_SERVER_MOTD, "VERSION %s %s", PACKAGE, VERSION);

    f = fopen (Motd_Path, "r");
    if (!f)
    {
	log ("show_motd(): %s: %s", Motd_Path, strerror (errno));
	return;
    }

    /* we don't call send_cmd() here because we want to avoid copying the
       buffer, just use it directly saving time */
    set_tag (Buf, MSG_SERVER_MOTD);
    while (fgets (Buf + 4, sizeof (Buf) - 4, f))
    {
	l = strlen (Buf + 4) - 1;
	set_len (Buf, l);
	queue_data (con, Buf, 4 + l);
    }
    fclose (f);
}
