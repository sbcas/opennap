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
	log ("textdb_init(): OUT OF MEMORY");
	return 0;
    }
    if ((db->stream = fopen (path, "r+")) == 0)
    {
	log ("textdb_init(): %s: %s (errno %d)", path, strerror (errno), errno);
	FREE (db);
	db = 0;
    }
    else
    {
	db->path = STRDUP (path);
	if (!db->path)
	{
	    log ("userdb_init(): OUT OF MEMORY");
	    fclose (db->stream);
	    FREE (db);
	    db = 0;
	}
    }
    return db;
}

void
textdb_free_result (TEXTDB_RES *p)
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
textdb_new_result (TEXTDB *db, LIST *columns)
{
    TEXTDB_RES *result = CALLOC (1, sizeof (TEXTDB_RES));

    if (result)
    {
	result->db = db;
	result->columns = columns;
    }
    return result;
}

static long
textdb_find_key (TEXTDB *db, const char *key, long *endOffset)
{
    int keyLen;
    long offset=0;

    ASSERT (db->stream != 0);
    ASSERT(key!=0);
    rewind(db->stream);
    keyLen = strlen (key);
    while (fgets (Buf, sizeof (Buf) - 1, db->stream))
    {
	if (!strncasecmp (Buf, key, keyLen) && isspace (Buf[keyLen]))
	{
	    if(endOffset)
		*endOffset=ftell(db->stream);
	    return offset;
	}
	offset = ftell (db->stream);
    }
    return -1;
}

TEXTDB_RES *
textdb_fetch (TEXTDB *db, const char *key)
{
    TEXTDB_RES *result;
    char *arg;
    long offset;

    ASSERT (db->stream != 0);
    offset = textdb_find_key (db, key, 0);
    if (offset == -1)
	return 0;
    fseek(db->stream,offset,0);
    result = CALLOC (1, sizeof (TEXTDB_RES));
    if (result)
    {
	result->db = db;
	arg = Buf;
	while (arg)
	    result->columns = list_append (result->columns, STRDUP (next_arg (&arg)));
    }
    return result;
}

int
textdb_store (TEXTDB_RES *result)
{
    FILE *tmpStream;
    LIST *list;
    int n;
    long offset, endOffset;

    offset=textdb_find_key(result->db,result->columns->data,&endOffset);
    if(offset==-1)
    {
	/* new record */
	fseek(result->db->stream,0,0);
	for (list = result->columns; list; list = list->next)
	{
	    if (list != result->columns)
		fputc (' ', result->db->stream);
	    fputs (list->data, result->db->stream);
	}
	fputc('\n',result->db->stream);
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
	unlink (Buf);	/* unlink here so the file disappears when we
			   close the stream */
	for (list = result->columns; list; list = list->next)
	{
	    if (list != result->columns)
		fputc (' ', tmpStream);
	    fputs (list->data, tmpStream);
	}
	fputc('\n',tmpStream);
	fseek (result->db->stream, endOffset, 0);
	while ((n = fread (Buf, 1, sizeof (Buf), result->db->stream)) > 0)
	    fwrite (Buf, 1, n, tmpStream);
	if (fflush (tmpStream))
	{
	    log ("textdb_store(): fflush: %s (errno %d)", strerror (errno),
		 errno);
	    fclose (tmpStream);
	    return -1;
	}
	fseek (result->db->stream, offset, 0);
	rewind (tmpStream);
	while ((n = fread (Buf, 1, sizeof (Buf), tmpStream)) > 0)
	    fwrite (Buf, 1, n, result->db->stream);
	fclose(tmpStream);
    }
    if (fflush (result->db->stream))
    {
	log ("textdb_store(): fflush: %s (errno %d)", strerror (errno),
	     errno);
	fclose (result->db->stream);
	return -1;
    }
    return 0;
}

void
textdb_close (TEXTDB *db)
{
    if (fflush (db->stream))
	log ("textdb_close(): fflush: %s (errno %d)", strerror (errno), errno);
    if (fclose (db->stream))
	log ("textdb_close(): fclose: %s (errno %d)", strerror (errno), errno);
    if (db->path)
	FREE (db->path);
    FREE (db);
}
