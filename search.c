/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#ifdef WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
#include <mysql.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdarg.h>
#include "opennap.h"
#include "debug.h"

extern MYSQL *Db;

/* convert spaces to % for SQL query, and quoted specials chars */
static void
format_request (const char *s, char *d, int dsize)
{
    for (; dsize > 1 && *s; s++)
    {
	if (*s == ' ')
	{
	    *d++ = '%';
	    while (ISSPACE (*(s + 1)))
		s++;
	}
	else if (*s == '\'' || *s == '%' || *s == '_' || *s == '\\')
	{
	    *d++ = '\\';
	    *d++ = *s;
	    dsize--;
	}
	else
	    *d++ = *s;
	dsize--;
    }
    *d = 0;
}

static void
append_string (char *d, int dsize, const char *fmt, ...)
{
    va_list ap;
    int l = strlen (d);

    va_start (ap, fmt);
    vsnprintf (d + l, dsize - l, fmt, ap);
    va_end (ap);
}

static char *
strlower (char *s)
{
    char *r = s;
    while (*s)
    	*s++ = tolower ((unsigned char)*s);
    return r;
}

HANDLER (search)
{
    char *fields[32], *p, data[32];
    MYSQL_RES *result;
    MYSQL_ROW row;
    USER *user;
    int i, numrows, numwords, max_results = Max_Search_Results, gottype = 0;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    CHECK_USER_CLASS ("search");

    log ("search: %s", pkt);

    numwords = split_line (fields, sizeof (fields) / sizeof (char *), pkt);
    ASSERT (numwords != 32); /* check to see if we had more fields */

    snprintf (Buf, sizeof (Buf), "SELECT * FROM library WHERE owner!='%s'",
	    con->user->nick);

    /* parse the request */
    for (i = 0; i < numwords; i++)
    {
	if (!strcasecmp ("filename", fields[i]) ||
	    !strcasecmp ("soundex", fields[i]))
	{
	    i++;
	    /* next word should be "contains" */
	    if (strcasecmp ("contains", fields[i]) != 0)
	    {
		send_cmd (con, MSG_SERVER_NOSUCH, "invalid search request");
		log
		    ("search: error in search string, expected '%s CONTAINS'",
		     fields[i - 1]);
		goto done;
	    }
	    i++;

	    /* remove trailing whitespace from request.  gnapster seems to add
	       this garbage */
	    p = fields[i] + strlen (fields[i]);
	    if (p > fields[i])
		p--;
	    while (ISSPACE (*p))
	    {
		*p = 0;
		if (p == fields[i])
		    break;
		p--;
	    }

	    /* convert for query */
	    format_request (fields[i], data, sizeof (data));
	    append_string (Buf, sizeof (Buf), " && %s LIKE '%%%s%%'",
		    strlower (fields[i-2]), data);
	}
	else if (strcasecmp ("max_results", fields[i]) == 0)
	{
	    /* the LIMIT clause goes last, so we save it for later
	       processing */
	    i++;
	    max_results = atoi (fields[i]);
	    if (max_results > Max_Search_Results)
	    {
		log ("search(): client requested a maximum of %d results",
			max_results);
		max_results = Max_Search_Results;
	    }
	}
	else if (!strcasecmp ("linespeed", fields[i]) ||
		!strcasecmp ("bitrate", fields[i]) ||
		!strcasecmp ("freq", fields[i]))
	{
	    i++;
	    if (i >= numwords - 1)
	    {
		send_cmd (con, MSG_SERVER_NOSUCH, "invalid search request");
		goto done;
	    }
	    if (!strcasecmp ("at least", fields[i]))
		p = ">=";
	    else if (!strcasecmp ("at most", fields[i]))
		p = "<=";
	    else if (!strcasecmp ("equals", fields[i]))
		p = "=";
	    else
	    {
		send_cmd (con, MSG_SERVER_NOSUCH, "invalid search request");
		goto done;
	    }
	    i++;
	    append_string (Buf, sizeof (Buf), " && %s%s%s", strlower (fields[i-2]),
		    p, fields[i]);
	}
	else if (!strcasecmp ("type", fields[i]))
	{
	    i++;
	    if (strcasecmp (fields[i], "any") != 0)
	    {
		format_request (fields[i], data, sizeof (data));
		append_string (Buf, sizeof (Buf), " && type LIKE '%%%s%%'",
			data);
	    }
	    gottype = 1;
	}
	else
	{
	    log ("search: unknown search field: %s", fields[i]);
	    send_cmd (con, MSG_SERVER_NOSUCH, "invalid search request");
	    goto done;
	}
    }

    /* if there was no type specified, assume the default of audio/mp3 to
       maintain backward compatibility */
    if (!gottype)
	append_string (Buf, sizeof (Buf), " && type='audio/mp3'");

    /* tag the maximum results to the end */
    append_string (Buf, sizeof (Buf), " LIMIT %d", max_results);

    log ("search: %s", Buf);

    if (mysql_query (Db, Buf) != 0)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "db error occured");
	sql_error ("search", Buf);
	goto done;
    }
    if ((result = mysql_store_result (Db)) == NULL)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "db error occured");
	log ("mysql_store_result() error");
	goto done;
    }
    numrows = mysql_num_rows (result);
    log ("search: %d matches", numrows);
    for (i = 0; i < numrows; i++)
    {
	row = mysql_fetch_row (result);

	/* find the user in our list */
	user = hash_lookup (Users, row[0]);
	if (!user)
	{
	    log ("search: user %s is no longer active!", row[0]);
	    continue;
	}

	send_cmd (con, MSG_SERVER_SEARCH_RESULT,
		  "\"%s\" %s %s %s %s %s %s %lu %d",
		  row[IDX_FILENAME],	/* filename */
		  row[IDX_MD5],		/* md5 */
		  row[IDX_SIZE],	/* size */
		  row[IDX_BITRATE],	/* bitrate */
		  row[IDX_FREQ],	/* sample rate */
		  row[IDX_LENGTH],	/* mp3 play length in secs */
		  row[IDX_NICK],	/* who has the file */
		  user->host,		/* ip of client holding file */
		  user->speed /* link speed */ );
    }
    mysql_free_result (result);

done:

    /* send end of search result message */
    send_cmd (con, MSG_SERVER_SEARCH_END, "");
}
