/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License. */

#include <unistd.h>
#include "opennap.h"

HANDLER (download_ack)
{
    (void) con;
    (void) pkt;

    /* if this message is in response to an upload request, we don't
       do anything except note that the upload is in progress */
    log ("download_ack(): entering");
}
