/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "opennap.h"
#include "debug.h"

typedef enum
{
    VAR_TYPE_INT,
    VAR_TYPE_STR
}
VAR_TYPE;

typedef struct config
{
    char *name;
    VAR_TYPE type;
    unsigned long val;
}
CONFIG;

static CONFIG Vars[] = {
    {"db_host", VAR_TYPE_STR, (unsigned long) &Db_Host},
    {"db_user", VAR_TYPE_STR, (unsigned long) &Db_User},
    {"db_pass", VAR_TYPE_STR, (unsigned long) &Db_Pass},
    {"db_name", VAR_TYPE_STR, (unsigned long) &Db_Name},
    { "max_user_channels", VAR_TYPE_INT, (unsigned long) &Max_User_Channels },
    {"motd_path", VAR_TYPE_STR, (unsigned long) &Motd_Path},
    {"server_name", VAR_TYPE_STR, (unsigned long) &Server_Name},
    {"server_password", VAR_TYPE_STR, (unsigned long) &Server_Pass},
    {"server_port", VAR_TYPE_INT, (unsigned long) &Server_Port}
};

static size_t Vars_Size = sizeof (Vars) / sizeof (CONFIG);

void
config (const char *path)
{
    FILE *f;
    char *ptr;
    size_t i;
    int line = 0;

    f = fopen (path, "r");
    if (!f)
    {
	perror (path);
	return;
    }
    log ("config(): reading %s", path);
    while (fgets (Buf, sizeof (Buf), f))
    {
	ptr = strrchr (Buf, '\n');
	if (ptr)
	    *ptr = 0;
	line++;
	ptr = Buf;
	while (isspace ((unsigned char) *ptr))
	    ptr++;
	if (*ptr == '#' || *ptr == 0)
	    continue;

	for (i = 0; i < Vars_Size; i++)
	{
	    if (strncmp (Vars[i].name, ptr, strlen (Vars[i].name)) == 0)
		break;
	}
	if (i == Vars_Size)
	{
	    log ("config(): error in %s, line %d: %s", path, line, Buf);
	    continue;
	}
	ptr += strlen (Vars[i].name);
	while (isspace ((unsigned char) *ptr))
	    ptr++;

	if (Vars[i].type == VAR_TYPE_STR)
	{
	    char **s = (char **) Vars[i].val;
	    if (*s)
		FREE (*s);
	    *s = STRDUP (ptr);
	}
	else if (Vars[i].type == VAR_TYPE_INT)
	{
	    int *l = (int *) Vars[i].val;
	    *l = atoi (ptr);
	}
    }
    fclose (f);
}
