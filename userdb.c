/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "opennap.h"
#include "debug.h"
#include "textdb.h"

static TEXTDB *User_Db = 0;

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

int
userdb_init (const char *path)
{
    ASSERT (User_Db == 0);
    ASSERT (path != 0);
    User_Db = textdb_init (path);
    return ((User_Db == 0));
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

USERDB *
userdb_fetch (const char *nick)
{
    TEXTDB_RES *result;
    LIST *list;
    USERDB *user;

    ASSERT (nick != 0);
    ASSERT (User_Db != 0);
    result = textdb_fetch (User_Db, nick);
    if (!result)
	return 0;
    if (list_count (result->columns) < 6)
    {
	log ("userdb_fetch(): too few columns in entry for user %s",
	     (char *) result->columns->data);
	textdb_free_result (result);
	return 0;
    }
    user = CALLOC (1, sizeof (USERDB));
    if (!user)
    {
	OUTOFMEMORY ("userdb_fetch");
	textdb_free_result (result);
	return 0;
    }
    list = result->columns;
    user->nick = STRDUP (list->data);
    list = list->next;
    user->password = STRDUP (list->data);
    list = list->next;
    user->email = STRDUP (list->data);
    list = list->next;
    user->level = get_level (list->data);
    if (user->level == -1)
	user->level = LEVEL_USER;
    list = list->next;
    user->created = atol (list->data);
    list = list->next;
    user->lastSeen = atol (list->data);
    if (!user->nick || !user->password || !user->email)
    {
	OUTOFMEMORY ("userdb_fetch");
	userdb_free (user);
	user = 0;
    }
    textdb_free_result (result);
    return user;
}

int
userdb_store (USERDB * db)
{
    LIST *list;
    char create[16], last[16];
    int err = 0;
    TEXTDB_RES *result;

    list = list_append (0, db->nick);
    list = list_append (list, db->password);
    list = list_append (list, db->email);
    list = list_append (list, Levels[db->level]);
    snprintf (create, sizeof (create), "%d", (int) db->created);
    list = list_append (list, create);
    snprintf (last, sizeof (last), "%d", (int) db->lastSeen);
    list = list_append (list, last);
    if ((result = textdb_new_result (User_Db, list)) == 0)
    {
	log ("userdb_store(): textdb_new_result failed");
	return -1;
    }
    if (textdb_store (result))
    {
	log ("userdb_store(): textdb_store failed");
	err = -1;
    }
    result->columns = 0;
    textdb_free_result (result);
    list_free (list, 0);
    return err;
}

void
userdb_close (void)
{
    textdb_close (User_Db);
}
