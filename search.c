/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "opennap.h"
#include "debug.h"

/* parameters for searching */
typedef struct {
    CONNECTION *con;
    int minbitrate;
    int maxbitrate;
    int minfreq;
    int maxfreq;
    int minspeed;
    int maxspeed;
    int type;		/* -1 means any type */
} SEARCH;

/* returns 0 if the match is not acceptable, nonzero if it is */
static int
search_callback (DATUM *match, SEARCH *parms)
{
#if 1
    /* don't return matches for a user's own files */
    if (match->user == parms->con->user)
        return 0;
#endif
    if (match->bitrate < parms->minbitrate)
        return 0;
    if (match->bitrate > parms->maxbitrate)
        return 0;
    if (match->user->speed < parms->minspeed)
        return 0;
    if (match->user->speed > parms->maxspeed)
        return 0;
    if (match->frequency < parms->minfreq)
        return 0;
    if (match->frequency > parms->maxfreq)
        return 0;
    if (parms->type != -1 && parms->type != match->type)
	return 0;	/* wrong content type */

    /* notify the user we found a match */
    send_cmd (parms->con, MSG_SERVER_SEARCH_RESULT,
        "\"%s\" %s %d %d %d %d %s %lu %d",
        match->filename,
        match->hash,
        match->size,
        match->bitrate,
        match->frequency,
        match->duration,
        match->user->nick,
        match->user->host,
        match->user->speed);

    return 1;/* accept match */
}

void
free_flist (FLIST *ptr)
{
    ASSERT ((ptr->count == 0) ^ (ptr->list != 0));
    FREE (ptr->key);
    list_free (ptr->list, (list_destroy_t) free_datum);
    FREE (ptr);
}

/* return a list of word tokens from the input string */
LIST *
tokenize (char *s)
{
    LIST *r = 0, *cur = 0;
    char *ptr;

    while (*s)
    {
        while (*s && !isalnum (*s))
            s++;
        ptr = s;
        while (*ptr && isalnum (*ptr))
            ptr++;
        if (*ptr)
            *ptr++ = 0;
        if (cur)
        {
            cur->next = list_new (s);
	    if (!cur->next)
		return r;
            cur = cur->next;
        }
        else
	{
            cur = r = list_new (s);
	    if (!cur)
		return 0;
	}
	strlower (cur->data); /* convert to lower case to save time */
        s = ptr;
    }
    return r;
}

void
free_datum (DATUM *d)
{
    ASSERT (d->refcount > 0);
    d->valid = 0;
    d->user = 0;
    d->refcount--;
    if (d->refcount == 0)
    {
	/* no more references, we can free this memory */
	FREE (d->filename);
	FREE (d->hash);
	FREE (d);
    }
}

typedef struct {
    int reaped;
    HASH *table;
} GARBAGE;

static void
collect_garbage (FLIST *files, GARBAGE *data)
{
    LIST *ptr, *last = 0;
    DATUM *d;

    ptr = files->list;
    while (ptr)
    {
	d = ptr->data;
	if (!d->valid)
	{
	    files->count--;
	    ++data->reaped;
	    if (last)
		last->next = ptr->next;
	    else
	    {
		/* first in list */
		files->list = ptr->next;
	    }
	    ptr->next = 0;
	    list_free (ptr, (list_destroy_t) free_datum);
	    if (!last)
	    {
		ptr = files->list;
		continue;
	    }
	    ptr = last; /* reset */
	}
	last = ptr;
	ptr = ptr->next;
    }

    if (files->count == 0)
    {
	/* no more files, remove this entry from the hash table */
	hash_remove (data->table, files->key);
    }
}

/* walk the table and remove invalid entries */
void
fdb_garbage_collect (HASH *table)
{
    GARBAGE data;

    data.reaped = 0;
    data.table = table;

    log ("fdb_garbage_collect(): collecting garbage");
    hash_foreach (table, (hash_callback_t) collect_garbage, &data);
    log ("fdb_garbage_collect(): reaped %d dead entries", data.reaped);
}

/* check to see if all the strings in list of tokens are present in the
   filename.  returns 1 if all tokens were found, 0 otherwise */
static int
match (LIST * tokens, const char *file)
{
    const char *b;
    char c[3], *a;
    int l;

    c[2] = 0;
    for (; tokens; tokens = tokens->next)
    {
        a = tokens->data;
        /* there doesn't appear to be a case-insensitive strchr() function
           so we fake it by using strpbrk() with a buffer that contains the
           upper and lower case versions of the char */
        c[0] = tolower (*a);
        c[1] = toupper (*a);
        l = strlen (a);
        b = file;
        while (*b)
        {
            b = strpbrk (b, c);
            if (!b)
                return 0;
            /* already compared the first char, see the if the rest of the
               string matches */
            if (!strncasecmp (b + 1, a + 1, l - 1))
                break;          /* matched, we are done with this token */
            b++; /* skip the matched char to find the next occurance */
        }
        if (!*b)
            return 0;   /* hit the end of the string before matching */
    }
    return 1;
}

static int
fdb_search (HASH *table,
	LIST *tokens,
	int maxhits,
	int (*cb) (DATUM *, SEARCH *),
	SEARCH *cbdata)
{
    LIST *ptok;
    FLIST *flist = 0, *tmp;
    DATUM *d;
    int hits = 0;

    /* find the file list with the fewest files in it */
    for (ptok = tokens; ptok; ptok = ptok->next)
    {
        tmp = hash_lookup (table, ptok->data);
	if (!tmp)
	{
	    /* if there is no entry for this word in the hash table, then
	       we know there are no matches */
	    return 0;
	}
        if (!flist || tmp->count < flist->count)
            flist = tmp;
    }
    if (!flist)
	return 0;	/* no matches */
    log ("fdb_search(): bin contains %d files", flist->count);
    /* find the list of files which contain all search tokens */
    for (ptok = flist->list;ptok;ptok=ptok->next)
    {
	d = (DATUM *) ptok->data;
	if (d->valid && match (tokens, d->filename) && cb (d, cbdata))
	{
	    /* callback accepted match */
	    hits++;
	    if (hits == maxhits)
		break;              /* finished */
	}
    }
    return hits;
}

/* 200 ... */
HANDLER (search)
{
    char *av[32];
    int ac, i, n, max_results = Max_Search_Results;
    LIST *tokens = 0;
    SEARCH parms;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    CHECK_USER_CLASS ("search");

    log ("search(): %s", pkt);

    ac = split_line (av, sizeof (av) / sizeof (char *), pkt);
    ASSERT (ac != 32); /* check to see if we had more av */

    memset (&parms, 0, sizeof (parms));
    parms.con = con;
    parms.maxspeed = 10;
    parms.maxbitrate = 0xffff;
    parms.maxfreq = 0xffff;
    parms.type = CT_MP3;	/* search for audio/mp3 by default */

    /* parse the request */
    for (i = 0; i < ac; i++)
    {
	if (!strcasecmp ("filename", av[i]))
	{
	    i++;
	    /* next word should be "contains" */
	    if (strcasecmp ("contains", av[i]) != 0)
	    {
		send_cmd (con, MSG_SERVER_NOSUCH, "invalid search request");
		log ("search(): error in search string, expected '%s CONTAINS'",
		     av[i - 1]);
		goto done;
	    }
	    i++;
	    /* do an implicit AND operation if multiple FILENAME CONTAINS
	       clauses are specified */
	    tokens = list_concat (tokens, tokenize (av[i]));
	}
	else if (strcasecmp ("max_results", av[i]) == 0)
	{
	    /* the LIMIT clause goes last, so we save it for later
	       processing */
	    i++;
	    max_results = atoi (av[i]);
	    if (Max_Search_Results && max_results > Max_Search_Results)
	    {
		log ("search(): client requested a maximum of %d results",
			max_results);
		max_results = Max_Search_Results;
	    }
	}
	else if (!strcasecmp ("type", av[i]))
	{
	    i++;
	    parms.type = -1;
	    for (n = CT_MP3; n < CT_UNKNOWN; n++)
	    {
		if (!strcasecmp (av[i], Content_Types[n]))
		{
		    parms.type = n;
		    break;
		}
	    }
	    if (parms.type == -1)
	    {
		send_cmd (con, MSG_SERVER_NOSUCH, "%s is an invalid type",
			av[i]);
		goto done;
	    }
	}
	else if (!strcasecmp ("linespeed", av[i]))
	{
	    i++;
	    if (i == ac - 1)
	    {
		send_cmd (con, MSG_SERVER_NOSUCH, "not enough parameters");
		goto done;
	    }
	    n = atoi (av[i+1]);
	    if (!strcasecmp ("at least", av[i]))
		parms.minspeed = n;
	    else if (!strcasecmp ("at most", av[i]))
		parms.maxspeed = n;
	    else if (!strcasecmp ("equal to", av[i]))
		parms.minspeed = parms.maxspeed = n;
	    else
	    {
		send_cmd (con, MSG_SERVER_NOSUCH,
			"\"%s\" is an unknown comparison", av[i]);
		goto done;
	    }
	    i++;
	}
	else if (!strcasecmp ("bitrate", av[i]))
	{
	    i++;
	    if (i == ac - 1)
	    {
		send_cmd (con, MSG_SERVER_NOSUCH, "not enough parameters");
		goto done;
	    }
	    n = atoi (av[i+1]);
	    if (!strcasecmp ("at least", av[i]))
		parms.minbitrate = n;
	    else if (!strcasecmp ("at most", av[i]))
		parms.maxbitrate = n;
	    else if (!strcasecmp ("equal to", av[i]))
		parms.minbitrate = parms.maxbitrate = n;
	    else
	    {
		send_cmd (con, MSG_SERVER_NOSUCH,
			"\"%s\" is an unknown comparison", av[i]);
		goto done;
	    }
	    i++;
	}
	else if (!strcasecmp ("freq", av[i]))
	{
	    i++;
	    if (i == ac - 1)
	    {
		send_cmd (con, MSG_SERVER_NOSUCH, "not enough parameters");
		goto done;
	    }
	    n = atoi (av[i+1]);
	    if (!strcasecmp ("at least", av[i]))
		parms.minfreq = n;
	    else if (!strcasecmp ("at most", av[i]))
		parms.maxfreq = n;
	    else if (!strcasecmp ("equal to", av[i]))
		parms.minfreq = parms.maxfreq = n;
	    else
	    {
		send_cmd (con, MSG_SERVER_NOSUCH,
			"\"%s\" is an unknown comparison", av[i]);
		goto done;
	    }
	    i++;
	}
	else
	{
	    log ("search(): unknown search field: %s", av[i]);
	    send_cmd (con, MSG_SERVER_NOSUCH, "invalid search request");
	    goto done;
	}
    }

    n = fdb_search (File_Table, tokens, max_results, search_callback, &parms);

    log ("search(): %d hits", n);

done:

    list_free (tokens, 0);

    /* send end of search result message */
    send_cmd (con, MSG_SERVER_SEARCH_END, "");
}
