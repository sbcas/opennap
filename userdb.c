/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include "opennap.h"
#include "debug.h"

HASH *User_Db = 0;

int
get_level (const char *s)
{
    if (!strncasecmp ("lee", s, 3))
	return LEVEL_LEECH;
    if (!strncasecmp ("use", s, 3))
	return LEVEL_USER;
    if (!strncasecmp ("mod", s, 3))
	return LEVEL_MODERATOR;
    if (!strncasecmp ("eli", s, 3))
	return LEVEL_ELITE;
    if (!strncasecmp ("adm", s, 3))
	return LEVEL_ADMIN;
    return -1;
}

void
userdb_free (USERDB * p)
{
    if (p)
    {
	if (p->nick)
	    FREE (p->nick);
	if (p->email)
	    FREE (p->email);
	if (p->password)
	    FREE (p->password);
	FREE (p);
    }
}

int
userdb_init (void)
{
    FILE *fp;
    int ac;
    char *av[6];
    USERDB *u;

    fp = fopen (User_Db_Path, "r");
    if (!fp)
    {
	logerr ("userdb_init", User_Db_Path);
	return -1;
    }
    User_Db = hash_init (257, (hash_destroy) userdb_free);
    log ("userdb_init(): reading %s", User_Db_Path);
    while (fgets (Buf, sizeof (Buf), fp))
    {
	ac = split_line (av, FIELDS (av), Buf);
	if (ac == 6)
	{
	    u = CALLOC (1, sizeof (USERDB));
	    if (u)
	    {
		u->nick = STRDUP (av[0]);
		u->password = STRDUP (av[1]);
		u->email = STRDUP (av[2]);
	    }
	    if (!u || !u->nick || !u->password || !u->email)
	    {
		OUTOFMEMORY ("userdb_init");
		if (u)
		    userdb_free (u);
		fclose (fp);
		return -1;
	    }
	    u->level = get_level (av[3]);
	    u->created = atol (av[4]);
	    u->lastSeen = atol (av[5]);
	    hash_add (User_Db, u->nick, u);
	}
	else
	{
	    log ("userdb_init(): bad user db entry");
	    print_args (ac, av);
	}
    }
    fclose (fp);
    log ("userdb_init(): %d registered users", User_Db->dbsize);
    return 0;
}

static void
dump_userdb (USERDB * db, FILE * fp)
{
    fputs (db->nick, fp);
    fputc (' ', fp);
    fputs (db->password, fp);
    fputc (' ', fp);
    fputs (db->email, fp);
    fputc (' ', fp);
    fputs (Levels[db->level], fp);
    fputc (' ', fp);
    fprintf (fp, "%d %d\r\n", (int) db->created, (int) db->lastSeen);
}

int
userdb_dump (void)
{
    FILE *fp;
    char path[_POSIX_PATH_MAX];

    log ("userdb_dump(): dumping user database");
    snprintf (path, sizeof (path), "%s.tmp", User_Db_Path);
    fp = fopen (path, "w");
    if (!fp)
    {
	logerr ("userdb_dump", path);
	return -1;
    }
    hash_foreach (User_Db, (hash_callback_t) dump_userdb, fp);
    if (fflush (fp))
    {
	logerr ("userdb_dump", "fflush");
	fclose (fp);
	return -1;
    }
    if (fclose (fp))
    {
	logerr ("userdb_dump", "fclose");
	return -1;
    }
    if (rename (path, User_Db_Path))
    {
	logerr ("userdb_dump", "rename");
	return -1;
    }
    log ("userdb_dump(): wrote %d entries", User_Db->dbsize);
    return 0;
}
