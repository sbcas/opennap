/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

/* TODO: this is pretty ugly and needs to be written more cleanly, and
   with bounds checking */

#include <mysql.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include "opennap.h"

extern MYSQL *Db;

#define APPEND(d,s) {l=strlen(d);snprintf(d+l,sizeof(d)-l,"%s",s);}

static void
convert_to_lower_case (char *s)
{
    for (; *s; s++)
	*s = tolower (*s);
}

/* convert spaces to % for SQL query, and quoted specials chars */
static void
format_request (const char *s, char *d, int dsize)
{
    for (;*s;s++)
    {
	if (*s == ' ')
	    *d++ = '%';
	else if (*s == '\'' || *s == '%' || *s == '_' || *s == '\\')
	{
	    *d++ = '\\';
	    *d++ = *s;
	}
	else
	    *d++ = *s;
    }
}

HANDLER (search)
{
    char *fields[32], *p;
    MYSQL_RES *result;
    MYSQL_ROW row;
    int i, numrows, numwords, max_results = 100, compound = 0;
    size_t l;
    USER *user;
    char quoted[128];

    CHECK_USER_CLASS ("search");

    log ("search(): %s", pkt);

    numwords = split_line (fields, sizeof (fields) / sizeof (char *), pkt);

    /* base search string, we add qualifiers to this */
    snprintf (Buf, sizeof (Buf), "SELECT * FROM library WHERE");

    /* parse the request */
    i = 0;
    while (i < numwords)
    {
	if (strcasecmp ("filename", fields[i]) == 0)
	{
	    i++;
	    /* next word should be "contains" */
	    if (strcasecmp ("contains", fields[i]) != 0)
	    {
		log
		    ("search(): error in search string, expected FILENAME CONTAINS");
		return;
	    }
	    i++;

	    /* remove trailing whitespace from request.  gnapster seems to add
	       this garbage */
	    p = fields[i] + strlen (fields[i]);
	    if (p > fields[i])
		p--;
	    while (isspace (*p))
	    {
		*p = 0;
		if (p == fields[i])
		    break;
		p--;
	    }

	    /* convert for SQL query */
	    format_request (fields[i], quoted, sizeof (quoted));

	    l = strlen (Buf);
	    snprintf (Buf + l, sizeof (Buf) - l, " %sfilename LIKE '%%%s%%'",
		    compound ? " && " : "", quoted);
	    i++;
	    compound = 1;
	}
	else if (strcasecmp ("max_results", fields[i]) == 0)
	{
	    /* the LIMIT clause goes last, so we save it for later
	       processing */
	    i++;
	    max_results = atoi (fields[i]);
	    if (max_results > 100)
	    {
		log ("search(): client requested a maximum of %d results",
			max_results);
		max_results = 100;
	    }
	    i++;
	}
	else if (strcasecmp ("linespeed", fields[i]) == 0 ||
		 strcasecmp ("bitrate", fields[i]) == 0 ||
		 strcasecmp ("freq", fields[i]) == 0)
	{
	    convert_to_lower_case (fields[i]);
	    l=strlen(Buf);
	    snprintf(Buf+l,sizeof(Buf)-l," %s%s", compound ? " && " : "",
		    fields[i]);
	    i++;
	    if (strcasecmp ("at least", fields[i]) == 0)
	    {
		APPEND (Buf, " > ");
	    }
	    else if (strcasecmp ("at most", fields[i]) == 0)
	    {
		APPEND (Buf, " < ");
	    }
	    else if (strcasecmp ("equals", fields[i]) == 0)
	    {
		APPEND (Buf, " = ");
	    }
	    else
	    {
		log ("search(): bad compare function: %s", fields[i]);
		return;
	    }
	    i++;
	    APPEND (Buf, fields[i]);
	    i++;
	    compound = 1;
	}
	else
	{
	    log ("search(): unknown search field: %s", fields[i]);
	    return;
	}
    }
    snprintf (Buf + strlen (Buf), sizeof (Buf) - strlen (Buf), " LIMIT %d",
	      max_results);

    log ("search(): %s", Buf);

    if (mysql_query (Db, Buf) != 0)
    {
	sql_error ("search", Buf);
	return;
    }
    if ((result = mysql_store_result (Db)) == NULL)
    {
	log ("mysql_store_result() error");
	return;
    }
    numrows = mysql_num_rows (result);
    log ("search(): %d matches", numrows);
    for (i = 0; i < numrows; i++)
    {
	row = mysql_fetch_row (result);

	/* find the user in our list */
	user = hash_lookup (Users, row[0]);
	if (!user)
	{
	    log ("search(): user %s is no longer active!", row[0]);
	    continue;
	}

	send_cmd (con, MSG_SERVER_SEARCH_RESULT,
		  "\"%s\" %s %s %s %s %s %s %d %d", row[IDX_FILENAME],	/* filename */
		  row[IDX_MD5],	/* md5 */
		  row[IDX_SIZE],	/* size */
		  row[IDX_BITRATE],	/* bitrate */
		  row[IDX_FREQ],	/* sample rate */
		  row[IDX_LENGTH],	/* mp3 play length in secs */
		  row[IDX_NICK],	/* who has the file */
		  user->host, user->speed /* link speed */ );
    }
    mysql_free_result (result);

    /* send end of search result message */
    send_cmd (con, MSG_SERVER_SEARCH_END, "");
}
