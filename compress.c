/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <zlib.h>
#include "opennap.h"
#include "debug.h"

/* 10200 <len><data>

   <len> is the uncompressed size
   <data> is the compressed data.  Contains 1 or more packets inside of it */
HANDLER (compressed_data)
{
    unsigned short len, tag;
    unsigned long offset = 0, datasize;
    unsigned char *data;

    ASSERT (validate_connection (con));
    CHECK_SERVER_CLASS("compressed_data");
    memcpy (&len, pkt, 2);
    len = BSWAP16(len);
    data = MALLOC (len);
    datasize = len;
    if (uncompress (data, &datasize, (unsigned char *) pkt + 2,
	    con->recvbytes - 6) != Z_OK)
    {
	log ("compressed_data(): unable to uncompress data");
	return;
    }
    if (datasize != len)
    {
	log ("compressed_data(): decompressed size did not match packet label");
	return;
    }
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
	len = BSWAP16(len);
	memcpy (&tag, con->recvhdr + 2, 2);
	tag = BSWAP16(tag);
	offset += 4;
	if (offset + len > datasize)
	{
	    log ("compressed_data(): not enough bytes left for packet body");
	    break; /* error */
	}
	if (len)
	{
	    /* make sure there is enough memory to hold this packet */
	    if (len + 1 > con->recvdatamax)
	    {
		con->recvdatamax = len + 1;
		con->recvdata = REALLOC (con->recvdata, con->recvdatamax);
	    }
	    memcpy (con->recvdata, data, len);
	}
	ASSERT (con->recvdata != 0);
	*(con->recvdata + len) = 0;

	/* handle this packet */
	dispatch_command (con, tag, len);

	offset += len;
    }
}
