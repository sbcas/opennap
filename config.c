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
    VAR_TYPE_STR,
    VAR_TYPE_BOOL
}
VAR_TYPE;

typedef struct config
{
    char *name;
    VAR_TYPE type;
    unsigned long val;
    unsigned long def;	/* default value */
}
CONFIG;

#define UL (unsigned long)

static CONFIG Vars[] = {
    { "db_host", VAR_TYPE_STR, UL &Db_Host, UL "localhost" },
    { "db_user", VAR_TYPE_STR, UL &Db_User, UL "mp3" },
    { "db_pass", VAR_TYPE_STR, UL &Db_Pass, UL "passtest" },
    { "db_name", VAR_TYPE_STR, UL &Db_Name, UL "mp3" },
    { "max_user_channels", VAR_TYPE_INT, UL &Max_User_Channels, 5 },
    { "motd_path", VAR_TYPE_STR, UL &Motd_Path, UL SHAREDIR "/motd" },
    { "server_name", VAR_TYPE_STR, UL &Server_Name, 0 },
    { "server_password", VAR_TYPE_STR, UL &Server_Pass, UL "opensource" },
    { "server_port", VAR_TYPE_INT, UL &Server_Port, 8888 },
    { "stat_click", VAR_TYPE_INT, UL &Stat_Click, 60 },
    { "strict_channels", VAR_TYPE_BOOL, OPTION_STRICT_CHANNELS, 0 }
};

static int Vars_Size = sizeof (Vars) / sizeof (CONFIG);

static void
set_int_var (CONFIG *v, int val)
{
    ASSERT (v->type == VAR_TYPE_INT);
    *(int*)v->val = val;
}

static void
set_str_var (CONFIG *v, const char *s)
{
    char **ptr;
    ASSERT (v->type == VAR_TYPE_STR);
    ptr = (char **) v->val;
    if (*ptr)
	FREE (*ptr);
    *ptr = STRDUP (s);
}

static int
set_var (const char *var, const char *val)
{
    int i, n;
    char *ptr;

    for (i = 0; i < Vars_Size; i++)
    {
	if(!strcmp(Vars[i].name, var))
	{
	    if(Vars[i].type == VAR_TYPE_INT)
	    {
		n = strtol (val, &ptr, 10);
		if (*ptr)
		    return -1;
		set_int_var (&Vars[i], n);
	    }
	    else if (Vars[i].type==VAR_TYPE_STR)
		set_str_var (&Vars[i], val);
	    else if (Vars[i].type == VAR_TYPE_BOOL)
	    {
		n = strtol (val, &ptr, 10);
		if (*ptr)
		    return -1;
		if (n)
		    Server_Flags |= Vars[i].val;
		else
		    Server_Flags &= ~Vars[i].val;
	    }
	    else
	    {
		ASSERT (0);
	    }
	    return 0;
	}
    }
    return -1;
}

void
config (const char *path)
{
    FILE *f;
    char *ptr, *val;
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
	val = strchr (ptr, ' ');
	if (val)
	{
	    *val++ = 0;
	    while (isspace (*val))
		val++;
	}

	if (set_var (ptr, val) != 0)
	    log ("config(): error in %s, line %d: %s=%s", path, line, ptr, val);
    }
    fclose (f);
}

/* 810 <var> <value> */
HANDLER (server_config)
{
    char *field[2];
    int i;

    ASSERT (validate_connection (con));
    ASSERT (validate_user (con->user));
    CHECK_USER_CLASS ("server_config");
    if (con->user->level < LEVEL_ELITE)
    {
	permission_denied (con);
	return;
    }
    if ((i = split_line (field, sizeof (field) / sizeof (char *), pkt)) < 1)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "wrong number of arguments");
	return;
    }

    if (i == 2)
	if (set_var (field[0], field[1]) != 0)
	{
	    send_cmd (con, MSG_SERVER_NOSUCH, "error setting variable %s",
		    field[0]);
	    return;
	}

    /* return the current value of the variable */
    for (i = 0; i < Vars_Size; i++)
    {
	if (!strcmp (pkt, Vars[i].name))
	{
	    if (Vars[i].type == VAR_TYPE_INT)
		send_cmd (con, MSG_SERVER_NOSUCH, "%s = %d", pkt,
			*(int*)Vars[i].val);
	    else if (Vars[i].type == VAR_TYPE_BOOL)
	    {
		send_cmd (con, MSG_SERVER_NOSUCH, "%s = %s", pkt,
			(Server_Flags & Vars[i].val) ? "on" : "off");
	    }
	    else
	    {
		ASSERT (Vars[i].type == VAR_TYPE_STR);
		send_cmd (con, MSG_SERVER_NOSUCH, "%s = %s", pkt,
			*(char**)Vars[i].val);
	    }
	    return;
	}
    }

    send_cmd (con, MSG_SERVER_NOSUCH, "no such variable %s", pkt);
}

void
free_config (void)
{
    int i;

    for (i = 0; i < Vars_Size; i++)
	if (Vars[i].type == VAR_TYPE_STR && *(char**)Vars[i].val)
	    FREE (* (char **) Vars[i].val);
}

void
config_defaults (void)
{
    int i;

    for (i = 0; i < Vars_Size; i++)
    {
	if (Vars[i].def)
	{
	    if (Vars[i].type == VAR_TYPE_STR)
		set_str_var (&Vars[i], (char*) Vars[i].def);
	    else if (Vars[i].type == VAR_TYPE_INT)
		set_int_var (&Vars[i], Vars[i].def);
	}
    }
}
