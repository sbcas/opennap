/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

/* generic flat file database where the first word is the key and the fields
   are space deliniated */

#include <ctype.h>
#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#ifndef WIN32
#include <unistd.h>
#endif
#include "opennap.h"
#include "debug.h"
#include "textdb.h"

TEXTDB *
textdb_init (const char *path)
{
    TEXTDB *db;

    db = CALLOC (1, sizeof (TEXTDB));
    if (!db)
    {
	OUTOFMEMORY ("textdb_init");
	return 0;
    }
    if ((db->stream = fopen (path, "r+")) == 0)
    {
	log ("textdb_init(): %s: %s (errno %d)", path, strerror (errno),
	     errno);
	FREE (db);
	db = 0;
    }
    else
    {
	db->path = STRDUP (path);
	if (!db->path)
	{
	    OUTOFMEMORY ("textdb_init");
	    fclose (db->stream);
	    FREE (db);
	    db = 0;
	}
    }
    return db;
}

void
textdb_free_result (TEXTDB_RES * p)
{
    LIST *list;

    if (p)
    {
	for (list = p->columns; list; list = list->next)
	    FREE (list->data);
	list_free (p->columns, 0);
	FREE (p);
    }
}

TEXTDB_RES *
textdb_new_result (TEXTDB * db, LIST * columns)
{
    TEXTDB_RES *result = CALLOC (1, sizeof (TEXTDB_RES));

    if (result)
    {
	result->db = db;
	result->columns = columns;
    }
    else
	OUTOFMEMORY ("textdb_new_result");
    return result;
}

static long
textdb_find_key (TEXTDB * db, const char *key, long *endOffset)
{
    int keyLen;
    long offset = 0;

    ASSERT (db->stream != 0);
    ASSERT (key != 0);
    rewind (db->stream);
    keyLen = strlen (key);
    while (fgets (Buf, sizeof (Buf) - 1, db->stream))
    {
	if (!strncasecmp (Buf, key, keyLen) && isspace (Buf[keyLen]))
	{
	    if (endOffset)
		*endOffset = ftell (db->stream);
	    return offset;
	}
	offset = ftell (db->stream);
    }
    return -1;
}

TEXTDB_RES *
textdb_fetch (TEXTDB * db, const char *key)
{
    TEXTDB_RES *result;
    char *arg;
    long offset;

    ASSERT (db->stream != 0);
    offset = textdb_find_key (db, key, 0);
    if (offset == -1)
	return 0;
    fseek (db->stream, offset, 0);
    result = CALLOC (1, sizeof (TEXTDB_RES));
    if (result)
    {
	result->db = db;
	arg = Buf;
	while (arg)
	    result->columns =
		list_append (result->columns, STRDUP (next_arg (&arg)));
    }
    else
	OUTOFMEMORY ("textdb_fetch");
    return result;
}

int
textdb_store (TEXTDB_RES * result)
{
    FILE *tmpStream;
    LIST *list;
    size_t n;
    long offset, endOffset;

    offset = textdb_find_key (result->db, result->columns->data, &endOffset);
    if (offset == -1)
    {
	/* new record */
	fseek (result->db->stream, 0, SEEK_END);
	for (list = result->columns; list; list = list->next)
	{
	    if (list != result->columns)
		if (fputc (' ', result->db->stream) == EOF)
		{
		    logerr ("textdb_store", "fputc");
		    return -1;
		}
	    if (fputs (list->data, result->db->stream) == EOF)
	    {
		logerr ("textdb_store", "fputs");
		return -1;
	    }
	}
#if USE_CRLF
	if (fputc ('\r', result->db->stream) == EOF)
	{
	    logerr ("textdb_store", "fputc");
	    return -1;
	}
#endif /* USE_CRLF */
	if (fputc ('\n', result->db->stream) == EOF)
	{
	    logerr ("textdb_store", "fputc");
	    return -1;
	}
    }
    else
    {
	snprintf (Buf, sizeof (Buf), "%s.tmp", result->db->path);
	tmpStream = fopen (Buf, "w+");
	if (!tmpStream)
	{
	    log ("textdb_store(): fopen: %s: %s (errno %d)", Buf,
		    strerror (errno), errno);
	    return -1;
	}
	unlink (Buf);		/* unlink here so the file disappears when we
				   close the stream */
	for (list = result->columns; list; list = list->next)
	{
	    if (list != result->columns)
		if (fputc (' ', tmpStream) == EOF)
		{
		    logerr ("textdb_store", "fputc");
		    fclose (tmpStream);
		    return -1;
		}
	    if (fputs (list->data, tmpStream) == EOF)
	    {
		logerr ("textdb_store", "fputs");
		fclose (tmpStream);
		return -1;
	    }
	}
#if USE_CRLF
	if (fputc ('\r', result->db->stream) == EOF)
	{
	    logerr ("textdb_store", "fputc");
	    return -1;
	}
#endif /* USE_CRLF */
	if (fputc ('\n', tmpStream) == EOF)
	{
	    logerr ("textdb_store", "fputc");
	    fclose (tmpStream);
	    return -1;
	}
	fseek (result->db->stream, endOffset, 0);
	while ((n = fread (Buf, 1, sizeof (Buf), result->db->stream)) > 0)
	{
	    if (fwrite (Buf, 1, n, tmpStream) != n)
	    {
		log ("textdb_store(): short write (fatal)");
		fclose (tmpStream);
		return -1;
	    }
	}
	if (fflush (tmpStream))
	{
	    logerr ("textdb_store", "fflush");
	    fclose (tmpStream);
	    return -1;
	}
	fseek (result->db->stream, offset, 0);
	rewind (tmpStream);
	while ((n = fread (Buf, 1, sizeof (Buf), tmpStream)) > 0)
	{
	    if (fwrite (Buf, 1, n, result->db->stream) != n)
	    {
		/* this is bad, the user database is now likely corrupted */
		log ("textdb_store(): FATAL ERROR: your user db is likely corrupted!!!");
		fclose (tmpStream);
		return -1;
	    }
	}
	fclose (tmpStream);
    }
    if (fflush (result->db->stream))
    {
	logerr ("textdb_store", "fflush");
	fclose (result->db->stream);
	return -1;
    }
    return 0;
}

void
textdb_close (TEXTDB * db)
{
    if (fflush (db->stream))
	logerr ("textdb_close", "fflush");
    if (fclose (db->stream))
	logerr ("textdb_close", "fclose");
    if (db->path)
	FREE (db->path);
    FREE (db);
}
