/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

static BUFFER *
buffer_new (void)
{
    BUFFER *r = CALLOC (1, sizeof (BUFFER));
#if DEBUG
    r->magic = MAGIC_BUFFER;
#endif
    return r;
}

/* append bytes to the buffer */
BUFFER *
buffer_queue (BUFFER *b, char *d, int dsize)
{
    BUFFER *r = b;

    if (!b)
	r = b = buffer_new ();
    else
    {
	ASSERT (buffer_validate (b));
	while (b->next)
	    b = b->next;
	if (b->consumed)
	{
	    /* buffer is partially written, create a new buffer */
	    b->next = buffer_new ();
	    b = b->next;
	}
    }
    b->data = REALLOC (b->data, b->datasize + dsize);
    memcpy (b->data + b->datasize, d, dsize);
    b->datasize += dsize;
    return r;
}

#if 0
static void
check_stream (BUFFER *b)
{
    ushort len, tag;
    int offset = b->consumed;
    BUFFER *c = b;

    while (offset + 4 <= c->datasize)
    {
	memcpy (&len, c->data + offset, 2);
	offset+=2;
	memcpy (&tag, c->data + offset, 2);
	offset+=2;
	if (tag == 100)
	{
	    if (*(c->data + offset) != ':')
	    {
		ASSERT (0);
	    }
	}
	offset += len;
    }
}
#endif

/* ensure that at least 'n' bytes exist in the first buffer fragment */
void
buffer_group (BUFFER *b, int n)
{
    ASSERT (buffer_validate (b));
    if (b->consumed + n > b->datasize)
    {
	int l = b->consumed + n - b->datasize;

	/* allocate 1 extra byte to hold a nul (\0) char */
	b->data = REALLOC (b->data, b->datasize + l + 1);
	ASSERT (b->next != 0);
	/* steal `l' bytes from the next buffer block */
	memcpy (b->data + b->datasize, b->next->data + b->next->consumed, l);
	b->datasize += l;
	*(b->data + b->datasize) = 0;
	b->next = buffer_consume (b->next, l);
    }
}

int
buffer_read (int fd, BUFFER **b)
{
    int n;
    BUFFER *p;

    n = read (fd, Buf, sizeof (Buf));
    if (n == -1)
    {
	log ("buffer_read: read: %s (errno %d)", strerror (errno), errno);
	return -1;
    }
    if (n == 0)
	return 0;

    if (!*b)
	*b = buffer_new ();
    ASSERT (buffer_validate (*b));
    p = *b;
    while (p->next)
	p = p->next;
    if (p->consumed)
    {
	p->next = buffer_new ();
	p = p->next;
    }
    /* we allocate one extra byte so that we can write a \0 in it for
       debuging */
    p->data = REALLOC (p->data, p->datasize + n + 1);
    memcpy (p->data + p->datasize, Buf, n);
    p->datasize += n;
    *(p->data + p->datasize) = 0;
    return n;
}

/* consume some bytes from the buffer */
BUFFER *
buffer_consume (BUFFER *b, int n)
{
    ASSERT (buffer_validate (b));
    ASSERT (b->consumed + n <= b->datasize);
    if (b->consumed + n > b->datasize)
    {
	ASSERT (0);
    }
    b->consumed += n;
    if (b->consumed >= b->datasize)
    {
	BUFFER *p = b;

	b = b->next;
	FREE (p->data);
	FREE (p);
    }
    return b;
}

BUFFER *
buffer_append (BUFFER *a, BUFFER *b)
{
    BUFFER *r = a;

    ASSERT (b != 0);
    if (!a)
	return b;
    ASSERT (buffer_validate (a));
    while (a->next)
	a = a->next;
    a->next = b;
    return r;
}

int
buffer_size (BUFFER *b)
{
    int n = 0;

    ASSERT (b == 0 || buffer_validate (b));
    for (; b; b = b->next)
	n += b->datasize - b->consumed;
    return n;
}

void
buffer_free (BUFFER *b)
{
    BUFFER *p;

    ASSERT (b == 0 || buffer_validate (b));
    while (b)
    {
	p = b;
	b = b->next;
	FREE (p->data);
	FREE (p);
    }
}

#if DEBUG
int
buffer_validate (BUFFER *b)
{
    ASSERT_RETURN_IF_FAIL (VALID_LEN (b, sizeof (BUFFER)), 0);
    ASSERT_RETURN_IF_FAIL (b->magic == MAGIC_BUFFER, 0);
    ASSERT_RETURN_IF_FAIL ((b->data == 0) ^ (b->datasize != 0), 0);
    ASSERT_RETURN_IF_FAIL (b->data == 0 || VALID_LEN (b->data, b->datasize), 0);
    ASSERT_RETURN_IF_FAIL (b->consumed == 0 || b->consumed < b->datasize, 0);
    ASSERT_RETURN_IF_FAIL (b->next == 0 || VALID_LEN (b->next, sizeof (BUFFER*)), 0);
    return 1;
}
#endif /* DEBUG */

#if HAVE_LIBZ
static BUFFER *
buffer_compress (z_streamp zip, BUFFER **b)
{
    BUFFER *r;
    int n, bytes, flush;

    ASSERT (buffer_validate (*b));

    /* in order to avoid blocking, we only compress `Compression_Threshold'
       bytes at a time, max */
    if ((*b)->datasize - (*b)->consumed > Compression_Threshold)
    {
	bytes = Compression_Threshold;
	flush = Z_NO_FLUSH;
    }
    else
    {
	bytes = (*b)->datasize - (*b)->consumed;
	/* if there is no more pending data, flush so we can send everything
	   together */
	flush = ((*b)->next != 0) ? Z_NO_FLUSH : Z_SYNC_FLUSH;
    }

#if 0
    log ("buffer_compress: compressing %d bytes (flush=%d)", bytes,
	    (flush == Z_SYNC_FLUSH));
#endif

    zip->next_in = (uchar *) (*b)->data + (*b)->consumed;
    zip->avail_in = bytes;

    r = buffer_new ();

    /* if flushing, loop until we get all the output from the compressor */
    do
    {
	r->data = REALLOC (r->data, r->datasize + bytes);
	zip->next_out = (uchar *) r->data + r->datasize;
	zip->avail_out = bytes;
	r->datasize += bytes;

	n = deflate (zip, flush);
	if (n != Z_OK)
	{
	    log ("buffer_compress: deflate: %s (error %d)",
		    NONULL (zip->msg), n);
	    FREE (r->data);
	    FREE (r);
	    return 0;
	}
    }
    while (flush == Z_SYNC_FLUSH && zip->avail_out == 0);

    ASSERT (zip->avail_in == 0);	/* should have compressed all data */

    if (flush == Z_SYNC_FLUSH && (unsigned int)bytes == zip->avail_in)
	log ("buffer_compress: huh? flush was set but didn't output anything");

    bytes -= zip->avail_in; /* sanity check, shouldn't be necessary unless
			       something fishy happened */

    r->datasize -= zip->avail_out;	/* remove extra space from output
					   buffer */
    *b = buffer_consume (*b, bytes);	/* pop the compressed bytes */

    if (r->datasize == 0)
    {
	/* nothing came out of the compressor, this means we probably
	   still have input pending */
	ASSERT (flush == Z_NO_FLUSH);
	FREE (r->data);
	FREE (r);
	return 0;
    }

#if 0
    log ("buffer_compress: compression ratio is %d%%",
	    (100 * (zip->total_in - zip->total_out)) / zip->total_in);
#endif

    return r;
}

/* assuming that we receive relatively short blocks via the network (less
   than 16kb), we uncompress all data when we receive it and don't worry
   about blocking. */
BUFFER *
buffer_uncompress (z_streamp zip, BUFFER **b)
{
    int n, flush;
    BUFFER *cur = 0;

    ASSERT (buffer_validate (*b));
    cur = buffer_new ();
    zip->next_in = (uchar *) (*b)->data + (*b)->consumed;
    zip->avail_in = (*b)->datasize - (*b)->consumed;
    while (zip->avail_in > 0)
    {
	/* allocate 2 times the compressed data for output, plus one extra
	   byte to terminate the string with a nul (\0) */
	cur->data = REALLOC (cur->data, cur->datasize + 2 * zip->avail_in + 1);
	zip->next_out = (uchar *) cur->data + cur->datasize;
	zip->avail_out = 2 * zip->avail_in;
	cur->datasize += 2 * zip->avail_in;

	/* if there is still more input after this, don't bother flushing */
	flush = ((*b)->next) ? Z_NO_FLUSH : Z_SYNC_FLUSH;
	n = inflate (zip, flush);
	if (n != Z_OK)
	{
	    log ("buffer_uncompress: inflate: %s (error %d)",
		NONULL (zip->msg), n);
	    FREE (cur->data);
	    FREE (cur);
	    return 0;
	}
	cur->datasize -= zip->avail_out;	/* subtract leftover space
						   because this is not real
						   data */
    }
    ASSERT (zip->avail_in == 0);	/* should have uncompressed all data */
    *b = buffer_consume (*b, (*b)->datasize - (*b)->consumed - zip->avail_in);

    /* if nothing came out, don't return an empty structure */
    if (cur->datasize == 0)
    {
	FREE (cur->data);
	FREE (cur);
	return 0;
    }

    /* we allocate one extra byte above for this nul char.  the
       handle_connection() routine expects this to be here since it needs
       to send only a portion of the string to the handler routines */
    *(cur->data + cur->datasize) = 0;

#if 0
    log ("buffer_uncompress: uncompression ratio is %d%%",
	    (100 * (zip->total_out - zip->total_in)) / zip->total_in);
#endif

    return cur;
}

void
init_compress (CONNECTION *con, int level)
{
    int n;

    ASSERT (validate_connection (con));
    ASSERT (con->class == CLASS_SERVER);
    con->zip = CALLOC (1, sizeof (ZIP));
    con->zip->zin = CALLOC (1, sizeof (z_stream));
    con->zip->zout = CALLOC (1, sizeof (z_stream));

    n = inflateInit (con->zip->zin);
    if (n != Z_OK)
    {
	log ("init_compress: inflateInit: %s (%d)",
		NONULL (con->zip->zin->msg), n);
    }
    n = deflateInit (con->zip->zout, level);
    if (n != Z_OK)
    {
	log ("init_compress: deflateInit: %s (%d)",
		NONULL (con->zip->zout->msg), n);
    }

    log ("init_compress: compressing server stream at level %d", level);
}

void
finalize_compress (ZIP *zip)
{
    int n;

    n = deflateEnd (zip->zout);
    if (n != Z_OK)
	log ("finalize_compress: deflateEnd: %s (%d)", NONULL (zip->zout->msg), n);
    n = inflateEnd (zip->zin);
    if (n != Z_OK)
	log ("finalize_compress: inflateEnd: %s (%d)", NONULL (zip->zin->msg), n);

    buffer_free (zip->outbuf);
    buffer_free (zip->inbuf);
    FREE (zip->zin);
    FREE (zip->zout);
    FREE (zip);
}
#endif

void
send_queued_data (CONNECTION *con)
{
    int n;

    ASSERT (validate_connection (con));

#if HAVE_LIBZ
    if (con->class == CLASS_SERVER)
    {
	BUFFER *r;

	ASSERT (con->zip != 0);
	if (con->zip->outbuf &&
	    (r = buffer_compress (con->zip->zout, &con->zip->outbuf)))
	    con->sendbuf = buffer_append (con->sendbuf, r);
    }
#endif

    /* is there data to write? */
    if (!con->sendbuf)
	return;	/* nothing to do */

    n = write (con->fd, con->sendbuf->data + con->sendbuf->consumed,
	con->sendbuf->datasize - con->sendbuf->consumed);
    if (n == -1)
    {
	log ("send_queued_data: write: %s (errno %d)", strerror (errno),
	    errno);
	con->destroy = 1;
	return;
    }

#if 0
    log ("send_queued_data: wrote %d bytes", n);
#endif

    if (n > 0)
	con->sendbuf = buffer_consume (con->sendbuf, n);

    n = (con->class == CLASS_SERVER) ? Server_Queue_Length : Client_Queue_Length;

    if (buffer_size (con->sendbuf) > n)
    {
	log ("send_queued_data: output buffer for %s exceeded %d bytes", 
		con->host, n);
	con->destroy = 1;
	return;
    }

    if (con->sendbuf)
	log ("send_queued_data: %d bytes remain in the output buffer",
		buffer_size (con->sendbuf));
}

void
queue_data (CONNECTION *con, char *s, int ssize)
{
    ASSERT (validate_connection (con));
    if (con->zip)
	con->zip->outbuf = buffer_queue (con->zip->outbuf, s, ssize);
    else
	con->sendbuf = buffer_queue (con->sendbuf, s, ssize);
}
