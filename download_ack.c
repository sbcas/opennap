/* Copyright (C) 1999 drscholl@hotmail.com
   This is free software distributed under the terms of the
   GNU Public License. */

#include <unistd.h>
#include "opennap.h"

void
download_ack (CONNECTION * con, char *pkt)
{
    (void) con;
    (void) pkt;

    /* if this message is in response to an upload request, we don't
       do anything except note that the upload is in progress */
    log ("download_ack(): entering");
}
