/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

/* NOTE: this file is deprecated and left for historical purposes */

#include <zlib.h>
#include "opennap.h"
#include "debug.h"

/* 10200 <len><data>

   <len> is the uncompressed size (4 bytes)
   <data> is the compressed data.  Contains 1 or more packets inside of it */
HANDLER (compressed_data)
{
    unsigned short len, tag;
    unsigned long offset = 0, datasize;
    unsigned char *data;
    unsigned int usize; /* uncompressed size */

    ASSERT (validate_connection (con));
    CHECK_SERVER_CLASS ("compressed_data");
    ASSERT (sizeof (usize) == 4);
    memcpy (&usize, pkt, 4);
    usize = BSWAP32 (usize);
    datasize = usize;
    if (usize == 0)
	return; /* empty packet */
    data = MALLOC (usize);
    if (uncompress (data, &datasize, (unsigned char *) pkt + 4,
	    con->recvbytes - 8) != Z_OK)
    {
	log ("compressed_data(): unable to uncompress data");
	goto error;
    }

    log ("compressed_data(): uncompressed %d bytes into %d bytes",
	    con->recvbytes - 8, datasize);

    /* handle each of the uncompressed packets */
    while (offset < datasize)
    {
	if (offset + 4 > datasize)
	{
	    log ("compressed_data(): not enough bytes left for packet header");
	    break; /* error */
	}
	memcpy (con->recvhdr, data + offset, 4);
	memcpy (&len, con->recvhdr, 2);
	len = BSWAP16 (len);
	memcpy (&tag, con->recvhdr + 2, 2);
	tag = BSWAP16 (tag);
	offset += 4;
	if (offset + len > datasize)
	{
	    log ("compressed_data(): packet length %hu with only %lu bytes left, tag=%hu",
		    len, datasize - offset, tag);
	    goto error;
	}
	if (len)
	{
	    /* make sure there is enough memory to hold this packet */
	    if (len + 1 > con->recvdatamax)
	    {
		con->recvdatamax = len + 1;
		con->recvdata = REALLOC (con->recvdata, con->recvdatamax);
	    }
	    memcpy (con->recvdata, data + offset, len);
	}
	ASSERT (con->recvdata != 0);
	*(con->recvdata + len) = 0;

	/* handle this packet */
	dispatch_command (con, tag, len);

	offset += len;
    }
error:
    FREE (data);
}
