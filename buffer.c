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
    r->data = mp_alloc (BufPool, 0);
    if (!r->data)
    {
	OUTOFMEMORY ("buffer_new");
	FREE (r);
	return 0;
    }
    r->datamax = BUFFER_SIZE;
    return r;
}

/* append bytes to the buffer */
static BUFFER *
buffer_queue (BUFFER * b, char *d, int dsize)
{
    BUFFER *r = b;
    int count;

    if (b)
	while (b->next)
	    b = b->next;
    while (dsize > 0)
    {
	if (!b)
	    r = b = buffer_new ();
	else if (b->datasize == b->datamax)
	{
	    b->next = buffer_new ();
	    b = b->next;
	}
	count = dsize;
	/* dsize could be greater than what is allocated */
	if (count > b->datamax - b->datasize)
	    count = b->datamax - b->datasize;
	memcpy (b->data + b->datasize, d, count);
	dsize -= count;
	d += count;
    }
    return r;
}

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
	mp_free (BufPool, p->data);
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
	mp_free (BufPool, p->data);
	FREE (p);
    }
}

#if DEBUG
int
buffer_validate (BUFFER * b)
{
#if 0
    /* does not work with mempool */
    ASSERT_RETURN_IF_FAIL (VALID_LEN (b, sizeof (BUFFER)), 0);
#endif
    ASSERT_RETURN_IF_FAIL (b->magic == MAGIC_BUFFER, 0);
    ASSERT_RETURN_IF_FAIL (b->datasize <= b->datamax, 0);
#if 0
    ASSERT_RETURN_IF_FAIL (b->data == 0
			   || VALID_LEN (b->data, b->datasize), 0);
#endif
    ASSERT_RETURN_IF_FAIL (b->consumed == 0 || b->consumed < b->datasize, 0);
#if 0
    ASSERT_RETURN_IF_FAIL (b->next == 0
			   || VALID_LEN (b->next, sizeof (BUFFER *)), 0);
#endif
    return 1;
}
#endif /* DEBUG */

static BUFFER *
buffer_compress (z_streamp zip, BUFFER ** b)
{
    BUFFER *r = 0, **pr;
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

    pr = &r;

    do
    {
	if (zip->avail_out == 0)
	{
	    /* allocate a new buffer to hold the rest of the compressed data */
	    *pr = buffer_new ();
	    if (!*pr)
		break;
	    /* mark the buffer as completely full then remove unused data
	       when we exit this loop */
	    (*pr)->datasize = BUFFER_SIZE;
	    zip->next_out = (unsigned char *) (*pr)->data;
	    zip->avail_out = BUFFER_SIZE;
	}
	n = deflate (zip, flush);
	if (n != Z_OK)
	{
	    log ("buffer_compress(): deflate: %s (error %d)",
		 NONULL (zip->msg), n);
	    break;
	}
	pr = &(*pr)->next;
    }
    while (zip->avail_out == 0 && flush == Z_SYNC_FLUSH);

    /* subtract any uncompressed bytes */
    bytes -= zip->avail_in;
    *b = buffer_consume (*b, bytes);

    if (r)
    {
	pr = &r;
	while ((*pr)->next)
	    pr = &(*pr)->next;
	(*pr)->datasize -= zip->avail_out;
	/* this should only happen for the first created buffer if the
	   input was small and there was a second buffer in the list */
	if ((*pr)->datasize == 0)
	{
	    ASSERT (r->next == 0);
	    if (r->next != 0)
		log ("buffer_compress(): ERROR! r->next was not NULL");
	    mp_free (BufPool, r->data);
	    FREE (r);
	    r = 0;
	}
    }

    return r;
}

/* assuming that we receive relatively short blocks via the network (less
   than 16kb), we uncompress all data when we receive it and don't worry
   about blocking.

   NOTE: this is the only buffer_*() function that does not use the memory
   pool.  each server gets its own real input buffer */
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
    do
    {
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
    }
    while (zip->avail_out == 0);
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

    log ("init_compress(): compressing server stream at level %d", level);
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

int
send_queued_data (CONNECTION * con)
{
    int n;

    ASSERT (validate_connection (con));

    if (ISSERVER (con))
    {
	BUFFER *r;

	if (con->sopt->outbuf &&
	    (r = buffer_compress (con->sopt->zout, &con->sopt->outbuf)))
	    con->sendbuf = buffer_append (con->sendbuf, r);
    }

    /* is there data to write? */
    if (!con->sendbuf)
	return 0;		/* nothing to do */

    n = WRITE (con->fd, con->sendbuf->data + con->sendbuf->consumed,
	       con->sendbuf->datasize - con->sendbuf->consumed);
    if (n == -1)
    {
	if (N_ERRNO != EWOULDBLOCK && N_ERRNO != EDEADLK)
	{
	    log ("send_queued_data(): write: %s (errno %d) for host %s",
		 strerror (N_ERRNO), N_ERRNO, con->host);
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
    n = (ISSERVER (con)) ? Server_Queue_Length : Client_Queue_Length;

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
	con->sopt->outbuf = buffer_queue (con->sopt->outbuf, s, ssize);
    else
	con->sendbuf = buffer_queue (con->sendbuf, s, ssize);
}
