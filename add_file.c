/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License. */

#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "opennap.h"
#include "debug.h"

extern MYSQL *Db;

/* this could be extended to handle generic data as well as mp3s */
#if 0
typedef enum
{
    ATTRTYPE_MIN,

    /* generic attributes */
    ATTRTYPE_OWNER = ATTRTYPE_MIN,
    ATTRTYPE_FILENAME,
    ATTRTYPE_MD5,
    ATTRTYPE_SIZE,
    ATTRTYPE_DATATYPE,

    /* mp3 attributes */
    ATTRTYPE_BITRATE,
    ATTRTYPE_SAMPLERATE,
    ATTRTYPE_TIME,

    ATTRTYPE_MAX
}
ATTRTYPE;

typedef struct _attribute
{
    ATTRTYPE type;
    char *val;
}
ATTRIBUTE;

static char *
get_attr (ATTRTYPE t, ATTRIBUTE * list, size_t listsize)
{
    int i;

    for (i = 0; i < listsize; i++)
    {
	if (t == list[i]->type)
	    return list[i].val;
    }
    return NULL;
}
#endif

/* adds a file to the database */

/* client request is of the form
   [ :<nick> ] <filename> <md5sum> <size> <bitrate> <frequency> <time> */

HANDLER (add_file)
{
    char *field[6];
    USER *user;

    ASSERT (VALID (con));

    if (pop_user (con, &pkt, &user) != 0)
	return;

    ASSERT (VALID (user));

    if (split_line (field, sizeof (field) / sizeof (char *), pkt) != 6)
    {
	log ("add_file(): wrong number of fields in message");
	return;
    }

    /* form the SQL request */
    snprintf (Buf, sizeof (Buf),
	      "INSERT INTO library VALUES('%s','%s',%s,'%s',%s,%s,%s,%d)",
	      user->nick, field[0], field[2], field[1],
	      field[3], field[4], field[5], user->speed);

    if (mysql_query (Db, Buf) != 0)
    {
	sql_error ("add_file", Buf);
	return;
    }

    log ("add_file(): user %s added file", user->nick);

    user->shared++;

    /* to avoid rounding errors in the total approximate size, we first
       subtract what we know this client has contributed, then recalculate
       the size in gigabytes */
    Num_Gigs -= user->libsize / 1024;
    user->libsize += atoi (field[2]) / 1024 / 1024; /* MB */
    Num_Gigs += user->libsize / 1024;	/* GB */

    Num_Files++;

    /* if this is a local connection, pass this information to our peer
       servers.  note that we prepend `:<nick>' so that the peer servers
       know who is adding the file. */
    if (con->class == CLASS_USER && Num_Servers)
    {
	pass_message_args (con, MSG_CLIENT_ADD_FILE,
		":%s \"%s\" %s %s %s %s %s", user->nick, field[0], field[1],
		field[2], field[3], field[4], field[5]);
    }
}
