/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$

   TODO: this is pretty ugly and needs to be written more cleanly, and
   with bounds checking */

#include <mysql.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"

extern MYSQL *Db;

/* convert spaces to % for SQL query, and quoted specials chars */
static void
format_request (const char *s, char *d, int dsize)
{
    if (dsize > 1)
    {
	*d++ = '%';
	dsize--;
    }
    for (; dsize > 2 && *s; s++)
    {
	if (*s == ' ')
	{
	    *d++ = '%';
	    while (isspace (*(s + 1)))
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
    if (dsize > 1)
    {
	*d++ = '%';
	dsize--;
    }
    *d = 0;
}

#if MINIDB
static int
glob_match (const char *pat, const char *s)
{
    char c;

    while (*pat && *s)
    {
	if (*pat == '_')
	{
	    /* match any char */
	}
	else if (*pat == '%')
	{
	    /* match 0 or more chars */
	    pat++;
	    c = tolower (*pat);
	    while (*s)
	    {
		while (*s && tolower (*s) != c)
		    s++;
		if (!*s)
		    break;
		if (glob_match (pat, s) == 1)
		    return 1;
		s++;
	    }
	    if (!*s)
		break;
	}
	else
	{
	    /* handle quoted chars */
	    if (*pat == '\\')
		pat++;
	    if (tolower (*pat) != tolower (*s))
		break;
	}
	s++; /* skip the matched char */
	pat++;
    }
    return (! (*pat || *s));
}
#endif /* MINIDB */

HANDLER (search)
{
    char *fields[32], *p;
#ifndef MINIDB
    MYSQL_RES *result;
    MYSQL_ROW row;
    int numrows;
    USER *user;
#endif
    int i, numwords, max_results = Max_Search_Results;
    char file[32];
    char soundex[32];
    char type[32];
    int minbitrate = 0, maxbitrate;
    int minfrequency = 0, maxfrequency;
    int minspeed = 0, maxspeed;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    CHECK_USER_CLASS ("search");

    file[0] = 0;
    soundex[0] = 0;
    strcpy (type, "audio/mp3");

#if MINIDB
    maxbitrate = 384;
    maxfrequency = 48000;
    maxspeed = 10;
#else
    maxbitrate = 0;
    maxfrequency = 0;
    maxspeed = 0;
#endif /* MINIDB */

    log ("search: %s", pkt);

    numwords = split_line (fields, sizeof (fields) / sizeof (char *), pkt);
    ASSERT (numwords != 32); /* check to see if we had more fields */

    /* parse the request */
    i = 0;
    while (i < numwords)
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
	    while (isspace (*p))
	    {
		*p = 0;
		if (p == fields[i])
		    break;
		p--;
	    }

	    /* convert for query */
	    if (!strcasecmp ("filename", fields[i-2]))
		format_request (fields[i], file, sizeof (file));
	    else
		format_request (fields[i], soundex, sizeof (soundex));
	    i++;
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
	    i++;
	}
	else if (!strcasecmp ("linespeed", fields[i]))
	{
	    i++;
	    if (i + 1 < numwords)
	    {
		if (!strcasecmp ("at least", fields[i]))
		    minspeed = atoi (fields[i+1]);
		else if (!strcasecmp ("at most", fields[i]))
		    maxspeed = atoi (fields[i+1]);
		else if (!strcasecmp ("equals", fields[i]))
		    maxspeed = minspeed = atoi (fields[i+1]);
		else
		{
		    send_cmd (con, MSG_SERVER_NOSUCH, "invalid search request");
		    goto done;
		}
		i += 2;
	    }
	    else
	    {
		send_cmd (con, MSG_SERVER_NOSUCH, "invalid search request");
		goto done;
	    }
	}
	else if (!strcasecmp ("bitrate", fields[i]))
	{
	    i++;
	    if (i + 1 < numwords)
	    {
		if (!strcasecmp ("at least", fields[i]))
		    minbitrate = atoi (fields[i+1]);
		else if (!strcasecmp ("at most", fields[i]))
		    maxbitrate = atoi (fields[i+1]);
		else if (!strcasecmp ("equals", fields[i]))
		    maxbitrate = minbitrate = atoi (fields[i+1]);
		else
		{
		    send_cmd (con, MSG_SERVER_NOSUCH, "invalid search request");
		    goto done;
		}
		i += 2;
	    }
	    else
	    {
		send_cmd (con, MSG_SERVER_NOSUCH, "invalid search request");
		goto done;
	    }
	}
	else if (!strcasecmp ("freq", fields[i]))
	{
	    i++;
	    if (i + 1 < numwords)
	    {
		if (!strcasecmp ("at least", fields[i]))
		    minfrequency = atoi (fields[i+1]);
		else if (!strcasecmp ("at most", fields[i]))
		    maxfrequency = atoi (fields[i+1]);
		else if (!strcasecmp ("equals", fields[i]))
		    maxfrequency = minfrequency = atoi (fields[i+1]);
		else
		{
		    send_cmd (con, MSG_SERVER_NOSUCH, "invalid search request");
		    goto done;
		}
		i += 2;
	    }
	    else
	    {
		send_cmd (con, MSG_SERVER_NOSUCH, "invalid search request");
		goto done;
	    }
	}
	else if (!strcasecmp ("type", fields[i]))
	{
	    i++;
	    if (!strcasecmp (fields[i], "any"))
		strcpy (type, "any");
	    else
		format_request (fields[i], type, sizeof (type));
	    i++;
	}
	else
	{
	    log ("search: unknown search field: %s", fields[i]);
	    send_cmd (con, MSG_SERVER_NOSUCH, "invalid search request");
	    goto done;
	}
    }

#if MINIDB
    for (i = 0; i < File_Table_Size && max_results > 0; i++)
    {
	if (File_Table[i]->user != con->user)
	{
	    if (file[0] && glob_match (file, File_Table[i]->filename) == 0)
		continue;
	    if (soundex[0] && glob_match (soundex, File_Table[i]->soundex) == 0)
		continue;
	    if (glob_match (type, File_Table[i]->type) == 0)
		continue;
	    if (minbitrate > File_Table[i]->bitrate)
		continue;
	    if (minspeed > File_Table[i]->user->speed)
		continue;
	    if (minfrequency >  File_Table[i]->samplerate)
		continue;
	    if (maxbitrate < File_Table[i]->bitrate)
		continue;
	    if (maxspeed < File_Table[i]->user->speed)
		continue;
	    if (maxfrequency < File_Table[i]->samplerate)
		continue;

	    send_cmd (con, MSG_SERVER_SEARCH_RESULT,
		    "\"%s\" %s %d %d %d %d %s %lu %d",
		    File_Table[i]->filename,
		    File_Table[i]->hash,
		    File_Table[i]->size,
		    File_Table[i]->bitrate,
		    File_Table[i]->samplerate,
		    File_Table[i]->length,
		    File_Table[i]->user->nick,
		    File_Table[i]->user->host,
		    File_Table[i]->user->speed);

	    max_results--;
	}
    }
#else
    snprintf (Buf, sizeof (Buf), "SELECT * FROM library WHERE owner!='%s'",
	    con->user->nick);
    if (file[0])
	snprintf (Buf + strlen(Buf), sizeof (Buf) - strlen(Buf),
		" && filename LIKE '%s'", file);
    if (soundex[0])
	snprintf (Buf + strlen(Buf), sizeof (Buf) - strlen(Buf),
		" && soundex LIKE '%s'", file);
    if (strcasecmp (type, "any"))
	snprintf (Buf + strlen(Buf), sizeof (Buf) - strlen(Buf),
		" && type LIKE '%s'", type);
    if (minbitrate)
	snprintf (Buf + strlen(Buf), sizeof (Buf) - strlen(Buf),
		" && bitrate>=%d", minbitrate);
    if (maxbitrate)
	snprintf (Buf + strlen(Buf), sizeof (Buf) - strlen(Buf),
		" && bitrate<=%d", maxbitrate);
    if (minfrequency)
	snprintf (Buf + strlen(Buf), sizeof (Buf) - strlen(Buf),
		" && freq>=%d", minfrequency);
    if (maxfrequency)
	snprintf (Buf + strlen(Buf), sizeof (Buf) - strlen(Buf),
		" && freq<=%d", maxfrequency);
    if (minspeed)
	snprintf (Buf + strlen(Buf), sizeof (Buf) - strlen(Buf),
		" && linespeed>=%d", minspeed);
    if (maxspeed)
	snprintf (Buf + strlen(Buf), sizeof (Buf) - strlen(Buf),
		" && linespeed<=%d", maxspeed);
    snprintf (Buf + strlen(Buf), sizeof (Buf) - strlen(Buf),
	    " LIMIT %d", max_results);

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
		  "\"%s\" %s %s %s %s %s %s %lu %d", row[IDX_FILENAME],	/* filename */
		  row[IDX_MD5],	/* md5 */
		  row[IDX_SIZE],	/* size */
		  row[IDX_BITRATE],	/* bitrate */
		  row[IDX_FREQ],	/* sample rate */
		  row[IDX_LENGTH],	/* mp3 play length in secs */
		  row[IDX_NICK],	/* who has the file */
		  user->host, user->speed /* link speed */ );
    }
    mysql_free_result (result);
#endif /* MINIDB */

done:

    /* send end of search result message */
    send_cmd (con, MSG_SERVER_SEARCH_END, "");
}
