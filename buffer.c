/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#ifndef WIN32
#include <unistd.h>
#include <sys/time.h>
#else
#include <windows.h>
#endif /* !WIN32 */
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

static BUFFER *
buffer_new (void)
{
    BUFFER *r = CALLOC (1, sizeof (BUFFER));

    if (!r)
    {
	OUTOFMEMORY ("buffer_new");
	return 0;
    }
#if DEBUG
    r->magic = MAGIC_BUFFER;
#endif
    return r;
}

/* append bytes to the buffer.  `step' is the size of a buffer to create if
   a new buffer needs to be created */
static BUFFER *
buffer_queue (BUFFER * b, char *d, int dsize, int step)
{
    BUFFER *r = b;

    if (!b)
    {
	r = b = buffer_new ();
	if (!b)
	    return 0;
	b->data = MALLOC (step);
	if (!b->data)
	{
	    OUTOFMEMORY ("buffer_queue");
	    FREE (b);
	    return 0;
	}
	b->datamax = step;
    }
    else
    {
	ASSERT (buffer_validate (b));
	while (b->next)
	    b = b->next;
	/* if there is not enough allocated data, allocate a new buffer
	   of size `step'.  we avoid using realloc() here because it is
	   potentially a very expensive operation
	   -or-
	   buffer is partially written, create a new buffer */
	if (b->datasize + dsize > b->datamax || b->consumed)
	{
	    b->next = buffer_new ();
	    if (!b->next)
		return r;
	    b->next->data = MALLOC (step);
	    if (!b->next->data)
	    {
		OUTOFMEMORY ("buffer_queue");
		FREE (b->next);
		b->next = 0;
		return r;
	    }
	    b = b->next;
	    b->datamax = step;
	}
    }
    memcpy (b->data + b->datasize, d, dsize);
    b->datasize += dsize;
    return r;
}

#ifdef WIN32
#undef errno
#define errno h_errno
#endif

/* consume some bytes from the buffer */
BUFFER *
buffer_consume (BUFFER * b, int n)
{
    ASSERT (buffer_validate (b));
    ASSERT (b->consumed + n <= b->datasize);
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
buffer_append (BUFFER * a, BUFFER * b)
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
buffer_size (BUFFER * b)
{
    int n = 0;

    ASSERT (b == 0 || buffer_validate (b));
    for (; b; b = b->next)
	n += b->datasize - b->consumed;
    return n;
}

void
buffer_free (BUFFER * b)
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
buffer_validate (BUFFER * b)
{
    ASSERT_RETURN_IF_FAIL (VALID_LEN (b, sizeof (BUFFER)), 0);
    ASSERT_RETURN_IF_FAIL (b->magic == MAGIC_BUFFER, 0);
    ASSERT_RETURN_IF_FAIL (b->datasize <= b->datamax, 0);
    ASSERT_RETURN_IF_FAIL (b->data == 0
			   || VALID_LEN (b->data, b->datasize), 0);
    ASSERT_RETURN_IF_FAIL (b->consumed == 0 || b->consumed < b->datasize, 0);
    ASSERT_RETURN_IF_FAIL (b->next == 0
			   || VALID_LEN (b->next, sizeof (BUFFER *)), 0);
    return 1;
}
#endif /* DEBUG */

#if HAVE_LIBZ
#define BUFFER_SIZE 16384

static BUFFER *
buffer_compress (z_streamp zip, BUFFER ** b)
{
    BUFFER *r = 0, *cur = 0;
    int n, bytes, flush;

    ASSERT (buffer_validate (*b));

    /* set up the input */
    bytes = (*b)->datasize - (*b)->consumed;
    zip->next_in = (uchar *) (*b)->data + (*b)->consumed;
    zip->avail_in = bytes;
    /* force a flush if this is the last input to compress */
    flush = ((*b)->next == 0) ? Z_SYNC_FLUSH : Z_NO_FLUSH;
    /* set to 0 so we allocate in the loop */
    zip->avail_out = 0;

    do {
	if (zip->avail_out == 0)
	{
	    /* allocate a new buffer to hold the rest of the compressed data */
	    if (cur)
	    {
		/* we should only get here if there was not enough room to
		   store the compressed output in the first buffer created */
		ASSERT (flush == Z_SYNC_FLUSH);
		log ("buffer_compress(): allocating additional buffer");
		cur->next = buffer_new ();
		if (!cur->next)
		    break;
		cur = cur->next;
	    }
	    else
	    {
		r = cur = buffer_new ();
		if (!r)
		    return 0;
	    }
	    cur->data = MALLOC (BUFFER_SIZE);
	    if (!cur->data)
	    {
		OUTOFMEMORY ("buffer_compress");
		break;
	    }
	    cur->datamax = BUFFER_SIZE;
	    cur->datasize = BUFFER_SIZE;
	    zip->next_out = (unsigned char *) cur->data;
	    zip->avail_out = BUFFER_SIZE;
	}

	n = deflate (zip, flush);
	if (n != Z_OK)
	{
	    log ("buffer_compress(): deflate: %s (error %d)",
		NONULL (zip->msg), n);
	    break;
	}
    }
    while (zip->avail_out == 0 && flush == Z_SYNC_FLUSH);

    /* subtract any uncompressed bytes */
    bytes -= zip->avail_in;
    *b = buffer_consume (*b, bytes);

    if (cur)
    {
	cur->datasize -= zip->avail_out;
	if (cur->datasize == 0)
	{
	    /* this should only happen for the first created buffer if the
	       input was small and there was a second buffer in the list */
	    ASSERT (cur == r);
	    FREE (r->data);
	    FREE (r);
	    r = 0 ;
	}
    }

    return r;
}

/* assuming that we receive relatively short blocks via the network (less
   than 16kb), we uncompress all data when we receive it and don't worry
   about blocking. */
int
buffer_decompress (BUFFER * b, z_streamp zip, char *in, int insize)
{
    int n;

    ASSERT (buffer_validate (b));
    ASSERT (insize > 0);
    zip->next_in = (unsigned char *) in;
    zip->avail_in = insize;
    zip->next_out = (unsigned char *) b->data + b->datasize;
    zip->avail_out = b->datamax - b->datasize;
    /* set this to the max size and subtract what is left after the inflate */
    b->datasize = b->datamax;
    do {
	/* if there is no more output space left, create some more */
	if (zip->avail_out == 0)
	{
	    /* allocate one extra byte to write a \0 char */
	    if (safe_realloc ((void **) &b->data, b->datamax + 2049))
	    {
		OUTOFMEMORY ("buffer_decompress");
		return -1;
	    }
	    b->datamax += 2048;
	    zip->next_out = (unsigned char *) b->data + b->datasize;
	    zip->avail_out = b->datamax - b->datasize;
	    /* set this to the max size and subtract what is left after the
	       inflate */
	    b->datasize = b->datamax;
	}
	n = inflate (zip, Z_SYNC_FLUSH);
	if (n != Z_OK)
	{
	    log ("buffer_decompress(): inflate: %s (error %d)",
		 NONULL (zip->msg), n);
	    return -1;
	}
    } while (zip->avail_out == 0);
    /* subtract unused bytes */
    b->datasize -= zip->avail_out;
    return 0;
}

void
init_compress (CONNECTION * con, int level)
{
    int n;

    ASSERT (validate_connection (con));
    ASSERT (ISSERVER (con));
    con->sopt->zin = CALLOC (1, sizeof (z_stream));
    if (!con->sopt->zin)
    {
	OUTOFMEMORY ("init_compress");
	return;
    }
    con->sopt->zout = CALLOC (1, sizeof (z_stream));
    if (!con->sopt->zout)
    {
	FREE (con->sopt->zin);
	OUTOFMEMORY ("init_compress");
	return;
    }

    n = inflateInit (con->sopt->zin);
    if (n != Z_OK)
    {
	log ("init_compress: inflateInit: %s (%d)",
	     NONULL (con->sopt->zin->msg), n);
    }
    n = deflateInit (con->sopt->zout, level);
    if (n != Z_OK)
    {
	log ("init_compress: deflateInit: %s (%d)",
	     NONULL (con->sopt->zout->msg), n);
    }

    log ("init_compress: compressing server stream at level %d", level);
}

void
finalize_compress (SERVER * serv)
{
    int n;

    n = deflateEnd (serv->zout);
    if (n != Z_OK)
	log ("finalize_compress: deflateEnd: %s (%d)",
	     NONULL (serv->zout->msg), n);
    n = inflateEnd (serv->zin);
    if (n != Z_OK)
	log ("finalize_compress: inflateEnd: %s (%d)",
	     NONULL (serv->zin->msg), n);
    FREE (serv->zin);
    FREE (serv->zout);
}
#endif

int
send_queued_data (CONNECTION * con)
{
    int n;

    ASSERT (validate_connection (con));

#if HAVE_LIBZ
    if (ISSERVER (con))
    {
	BUFFER *r;

	if (con->sopt->outbuf &&
	    (r = buffer_compress (con->sopt->zout, &con->sopt->outbuf)))
	    con->sendbuf = buffer_append (con->sendbuf, r);
    }
#endif

    /* is there data to write? */
    if (!con->sendbuf)
	return 0;		/* nothing to do */

    n = WRITE (con->fd, con->sendbuf->data + con->sendbuf->consumed,
	       con->sendbuf->datasize - con->sendbuf->consumed);
    if (n == -1)
    {
	if (errno != EWOULDBLOCK && errno != EDEADLK)
	{
	    log ("send_queued_data(): write: %s (errno %d)",
		 strerror (errno), errno);
	    return -1;
	}
	return 0;
    }
    else if (n > 0)
    {
	/* mark data as written */
	con->sendbuf = buffer_consume (con->sendbuf, n);
    }
    /* keep track of the outgoing bandwidth */
    Bytes_Out += n;

    /* check to make sure the queue hasn't gotten too big */
    n =
	(con->class ==
	 CLASS_SERVER) ? Server_Queue_Length : Client_Queue_Length;

    if (buffer_size (con->sendbuf) > n)
    {
	log ("send_queued_data(): output buffer for %s exceeded %d bytes",
	     con->host, n);
	return -1;
    }

    return 0;
}

void
queue_data (CONNECTION * con, char *s, int ssize)
{
    ASSERT (validate_connection (con));
    if (ISSERVER (con))
    {
	/* for a server connection, allocate chunks of 16k bytes */
	con->sopt->outbuf = buffer_queue (con->sopt->outbuf, s, ssize, 16384);
    }
    else
	/* for a client connection, allocate chunks of 1k bytes */
	con->sendbuf = buffer_queue (con->sendbuf, s, ssize, 1024);
}
