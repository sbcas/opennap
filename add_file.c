/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.

   $Id$ */

#ifdef WIN32
#include <windows.h>
#endif
#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "opennap.h"
#include "debug.h"

extern MYSQL *Db;

static void
compute_soundex (char *d, int dsize, const char *s)
{
    int n = 0;

    /* if it's not big enough to hold one soundex word, quit without
       doing anything */
    if (dsize < 4)
    {
	ASSERT (0);		/* this is a programming error */
	if (dsize > 0)
	    *d = 0;
	return;
    }
    dsize--;			/* save room for the terminatin nul (\0) */

    while (*s && !isalpha (*s))
	s++;
    if (!*s)
    {
	*d = 0;
	return;
    }

    *d++ = toupper (*s);
    dsize--;
    s++;

    while (*s && dsize > 0)
    {
	switch (tolower (*s))
	{
	case 'b':
	case 'p':
	case 'f':
	case 'v':
	    if (n < 3)
	    {
		*d++ = '1';
		dsize--;
		n++;
	    }
	    break;
	case 'c':
	case 's':
	case 'k':
	case 'g':
	case 'j':
	case 'q':
	case 'x':
	case 'z':
	    if (n < 3)
	    {
		*d++ = '2';
		dsize--;
		n++;
	    }
	    break;
	case 'd':
	case 't':
	    if (n < 3)
	    {
		*d++ = '3';
		dsize--;
		n++;
	    }
	    break;
	case 'l':
	    if (n < 3)
	    {
		*d++ = '4';
		dsize--;
		n++;
	    }
	    break;
	case 'm':
	case 'n':
	    if (n < 3)
	    {
		*d++ = '5';
		dsize--;
		n++;
	    }
	    break;
	case 'r':
	    if (n < 3)
	    {
		*d++ = '6';
		dsize--;
		n++;
	    }
	    break;
	default:
	    if (!isalpha (*s))
	    {
		/* pad short words with 0's */
		while (n < 3 && dsize > 0)
		{
		    *d++ = '0';
		    dsize--;
		    n++;
		}
		n = 0;		/* reset */
		/* skip forward until we find the next word */
		s++;
		while (*s && !isalpha (*s))
		    s++;
		if (!*s)
		{
		    *d = 0;
		    return;
		}
		if (dsize > 0)
		{
		    *d++ = ',';
		    dsize--;
		    if (dsize > 0)
		    {
			*d++ = toupper (*s);
			dsize--;
		    }
		}
	    }
	    /* else it's a vowel and we ignore it */
	    break;
	}
	/* skip over duplicate letters */
	while (*(s + 1) == *s)
	    s++;

	/* next letter */
	s++;
    }
    /* pad short words with 0's */
    while (n < 3 && dsize > 0)
    {
	*d++ = '0';
	dsize--;
	n++;
    }
    *d = 0;
}

static void
share_common (USER *user, int fsize /* file size in kbytes */)
{
    user->shared++;

    /* to avoid rounding errors in the total approximate size, we first
       subtract what we know this client has contributed, then recalculate
       the size in gigabytes */
    user->libsize += fsize;
    Num_Gigs += fsize;		/* this is actually kB, not gB */
    Num_Files++;
}

/* adds a file to the database
   [ :<nick> ] <filename> <md5sum> <size> <bitrate> <frequency> <time> */

HANDLER (add_file)
{
    char *field[6], soundex[256], *p, path[256];
    USER *user;
    unsigned int fsize;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &user) != 0)
	return;

    ASSERT (validate_user (user));

    if (split_line (field, sizeof (field) / sizeof (char *), pkt) != 6)
    {
	log ("add_file: wrong number of fields in message");
	if (con->class == CLASS_USER)
	    send_cmd (con, MSG_SERVER_NOSUCH,
		    "invalid parameter data to add a file");
	return;
    }

    if (user->shared == Max_Shared)
    {
	if (user->con)
	    send_cmd (user->con, MSG_SERVER_NOSUCH,
		      "You may only share %d files.", Max_Shared);
	return;
    }
    /* skip over the leading path name to get just the filename.  we compute
       the soundex hash of the filename to support soundex searching in
       the clients */
    p = strrchr (field[0], '\\');
    if (!p)
	p = field[0];
    else
	p++;			/* skip the backslash */
    compute_soundex (soundex, sizeof (soundex), p);

    /* sql will take DOS path names with backslashes to mean the escape
       char, so we have to escape them here */
    fudge_path (field[0], path, sizeof (path));

    /* form the SQL request */
    snprintf (Buf, sizeof (Buf),
	      "INSERT INTO library VALUES('%s','%s',%s,'%s',%s,%s,%s,%d,'%s','audio/mp3')",
	      user->nick, path, field[2], field[1],
	      field[3], field[4], field[5], user->speed, soundex);

    if (mysql_query (Db, Buf) != 0)
    {
	sql_error ("add_file", Buf);
	if (con->class == CLASS_USER)
	    send_cmd (con, MSG_SERVER_NOSUCH,
		      "error adding file to database");
	return;
    }

    /* if this is a local connection, pass this information to our peer
       servers.  note that we prepend `:<nick>' so that the peer servers
       know who is adding the file. */
    if (con->class == CLASS_USER && Num_Servers)
    {
	pass_message_args (con, MSG_CLIENT_ADD_FILE,
			   ":%s \"%s\" %s %s %s %s %s", user->nick, field[0],
			   field[1], field[2], field[3], field[4], field[5]);
    }

    fsize = atol (field[2]) / 1024;	/* file size in kB */
    share_common (user, fsize);
}

/* 10300 [ :<user> ] "<filename>" <size> <hash> <content-type> */
HANDLER (share_file)
{
    char *field[4], path[256], soundex[256], *p;
    USER *user;

    (void) len;
    (void) tag;

    ASSERT (validate_connection (con));

    if (pop_user (con, &pkt, &user) != 0)
	return;

    if (split_line (field, sizeof (field) / sizeof (char *), pkt) != 4)
    {
	log ("share_file(): wrong number of fields");
	if (user->con)
	    send_cmd (user->con, MSG_SERVER_NOSUCH, "wrong number of fields");
	return;
    }

    /* make sure the content-type looks correct */
    if (strncasecmp ("audio/", field[3], 6) &&
	strncasecmp ("image/", field[3], 6) &&
	strncasecmp ("video/", field[3], 6) &&
	strncasecmp ("application/", field[3], 11) &&
	strncasecmp ("text/", field[3], 5))
    {
	log ("share_file(): not a MIME type: %s", field[3]);
	if (user->con)
	    send_cmd (user->con, MSG_SERVER_NOSUCH,
		      "%s is not a valid MIME content-type", field[3]);
	return;
    }

    fudge_path (field[0], path, sizeof (path));
    p = strrchr (field[0], '\\');
    if (p)
	p++;
    else
	p = field[0];
    compute_soundex (soundex, sizeof (soundex), p);
    snprintf (Buf, sizeof (Buf),
	      "INSERT INTO library VALUES ('%s','%s',%s,'%s',0,0,0,%d,'%s','%s')",
	      user->nick, path, field[1], field[2], user->speed, soundex,
	      field[3]);
    if (mysql_query (Db, Buf) != 0)
    {
	sql_error ("share_file", Buf);
	if (user->con)
	    send_cmd (user->con, MSG_SERVER_NOSUCH,
		      "error adding file to db");
	return;
    }
    if (con->class == CLASS_USER && Num_Servers)
    {
	pass_message_args (con, MSG_CLIENT_SHARE_FILE, ":%s \"%s\" %s %s %s",
			   user->nick, field[0], field[1], field[2],
			   field[3]);
    }

    share_common (user, strtol (field[1], 0, 10) / 1024);
}
