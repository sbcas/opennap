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
	log ("buffer_new(): ERROR: OUT OF MEMORY");
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
buffer_queue (BUFFER *b, char *d, int dsize, int step)
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
	    log ("buffer_queue(): ERROR: OUT OF MEMORY");
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
		log ("buffer_queue(): ERROR: OUT OF MEMORY");
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

/* ensure that at least 'n' bytes exist in the first buffer fragment */
int
buffer_group (BUFFER *b, int n)
{
    ASSERT (buffer_validate (b));
    if (b->consumed + n > b->datasize)
    {
	int l = b->consumed + n - b->datasize;

	/* allocate 1 extra byte to hold a nul (\0) char */
	b->datamax = b->datasize + l + 1;
	if (safe_realloc ((void **) &b->data, b->datamax))
	{
	    log ("buffer_group(): ERROR: OUT OF MEMORY");
	    /* this will probably not make some of the other routines happy
	       because they don't expect a 0 byte buffer at the beginning
	       of the list, but its better than dumping core here */
	    if (b->data)
		FREE (b->data);
	    b->datasize = b->datamax = b->consumed = 0;
	    return -1;
	}
	ASSERT (b->next != 0);
	/* steal `l' bytes from the next buffer block */
	ASSERT (b->next->datasize >= l);
	memcpy (b->data + b->datasize, b->next->data + b->next->consumed, l);
	b->datasize += l;
	*(b->data + b->datasize) = 0;
	b->next = buffer_consume (b->next, l);
    }
    return 0;
}

#ifdef WIN32
#undef errno
#define errno h_errno
#endif

int
buffer_read (int fd, BUFFER **b)
{
    int n;
    BUFFER *p;

    n = READ (fd, Buf, sizeof (Buf));
    if (n == -1)
    {
	log ("buffer_read(): read: %s (errno %d)", strerror (errno), errno);
	return -1;
    }
    if (n == 0)
	return 0;

    if (!*b)
    {
	*b = buffer_new ();
	if (!*b)
	    return -1;
    }
    ASSERT (buffer_validate (*b));
    p = *b;
    while (p->next)
	p = p->next;
    if (p->consumed)
    {
	p->next = buffer_new ();
	if (!p->next)
	    return -1;
	p = p->next;
    }
    /* we allocate one extra byte so that we can write a \0 in it for
       debuging */
    p->datamax = p->datasize + n + 1;
    p->data = REALLOC (p->data, p->datamax);
    if (!p->data)
    {
	log ("buffer_read(): ERROR: OUT OF MEMORY");
	return -1;
    }
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
    ASSERT_RETURN_IF_FAIL (b->datasize <= b->datamax, 0);
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

    r = buffer_new();
    if (!r)
	return 0; /* out of memory */
    r->data = MALLOC (16384);
    if (!r->data)
    {
	log ("buffer_compress(): ERROR: OUT OF MEMORY");
	FREE (r);
	return 0;
    }
    r->datamax = 16384;
    /* we subtract the unused portion of the buffer after the loop */
    r->datasize = 16384;

    /* set up the output */
    zip->next_out = (uchar *) r->data;
    zip->avail_out = r->datamax;

    do
    {
	bytes = (*b)->datasize - (*b)->consumed;

	/* set up the input */
	zip->next_in = (uchar *) (*b)->data + (*b)->consumed;
	zip->avail_in = bytes;

	/* force a flush if this is the last input to compress */
	flush = (bytes == buffer_size (*b)) ? Z_SYNC_FLUSH : Z_NO_FLUSH;

	n = deflate (zip, flush);
	if (n != Z_OK)
	{
	    log ("buffer_compress(): deflate: %s (error %d)",
		    NONULL (zip->msg), n);
	    break;
	}

	bytes -= zip->avail_in;
	*b = buffer_consume (*b, bytes);
    }
    while (*b != 0 && zip->avail_out > 0);

    r->datasize -= zip->avail_out;

    /* if we produced no output, return NULL instead of an empty buffer */
    if (r->datasize == 0)
    {
	FREE (r->data);
	FREE (r);
	r = 0;
    }

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
    if (!cur)
	return 0;
    zip->next_in = (uchar *) (*b)->data + (*b)->consumed;
    zip->avail_in = (*b)->datasize - (*b)->consumed;
    while (zip->avail_in > 0)
    {
	/* allocate 2 times the compressed data for output, plus one extra
	   byte to terminate the string with a nul (\0) */
	n = 2 * zip->avail_in;
	cur->datamax = cur->datasize + n + 1;
	cur->data = REALLOC (cur->data, cur->datamax);
	if (!cur->data)
	{
	    log ("buffer_uncompress(): ERROR: OUT OF MEMORY");
	    FREE (cur);
	    return 0;
	}
	zip->next_out = (uchar *) cur->data + cur->datasize;
	zip->avail_out = n;
	cur->datasize += n; /* we subtract leftover bytes after the inflate()
			       call below */

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

    return cur;
}

void
init_compress (CONNECTION *con, int level)
{
    int n;

    ASSERT (validate_connection (con));
    ASSERT (con->class == CLASS_SERVER);
    con->zip = CALLOC (1, sizeof (ZIP));
    if (!con->zip)
    {
	log ("init_compress(): ERROR: OUT OF MEMORY");
	return;
    }
    con->zip->zin = CALLOC (1, sizeof (z_stream));
    if (!con->zip->zin)
    {
	FREE (con->zip);
	log ("init_compress(): ERROR: OUT OF MEMORY");
	return;
    }
    con->zip->zout = CALLOC (1, sizeof (z_stream));
    if (!con->zip->zout)
    {
	FREE (con->zip->zin);
	FREE (con->zip);
	log ("init_compress(): ERROR: OUT OF MEMORY");
	return;
    }

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

int
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
	return 0; /* nothing to do */

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

    /* check to make sure the queue hasn't gotten too big */
    n = (con->class == CLASS_SERVER) ? Server_Queue_Length : Client_Queue_Length;

    if (buffer_size (con->sendbuf) > n)
    {
	log ("send_queued_data(): output buffer for %s exceeded %d bytes", 
	    con->host, n);
	return -1;
    }

    if (con->sendbuf)
	log ("send_queued_data(): %d bytes remain in the output buffer for %s",
	    buffer_size (con->sendbuf), con->host);

    return 0;
}

void
queue_data (CONNECTION *con, char *s, int ssize)
{
    ASSERT (validate_connection (con));
    if (con->zip)
	/* for a server connection, allocate chunks of 16k bytes */
	con->zip->outbuf = buffer_queue (con->zip->outbuf, s, ssize, 16384);
    else
	/* for a client connection, allocate chunks of 1k bytes */
	con->sendbuf = buffer_queue (con->sendbuf, s, ssize, 1024);
}
