/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#ifdef WIN32
#include <windows.h>
#endif /* WIN32 */
#include <mysql.h>
#include <stdio.h>
#include "opennap.h"

MYSQL *Db = NULL;

int
init_db (void)
{
    MYSQL *d;

    Db = mysql_init (Db);
    if (Db == NULL)
    {
	log ("init_db(): mysql_init failed");
	return -1;
    }
    d = mysql_connect (Db, Db_Host, Db_User, Db_Pass);
    if (d == NULL)
    {
	log ("init_db(): mysql_connect: %s", mysql_error (Db));
	return -1;
    }
    Db = d;
    if (mysql_select_db (Db, Db_Name))
    {
	log ("init_db(): mysql_select_db: %s", mysql_error (Db));
	return -1;
    }

    return 0;
}

/* generic error function to call when mysql_query() has failed. */
void
sql_error (const char *func, const char *query)
{
    log ("%s(): %s", func, query);
    log ("%s(): %s (error %d)", func, mysql_error (Db), mysql_errno (Db));
}

void
close_db (void)
{
    mysql_close (Db);
}
