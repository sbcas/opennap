/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

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
    { "max_user_channels", VAR_TYPE_INT, UL &Max_User_Channels, 5 },
    { "motd_path", VAR_TYPE_STR, UL &Motd_Path, UL SHAREDIR "/motd" },
    { "server_name", VAR_TYPE_STR, UL &Server_Name, 0 },
    { "server_password", VAR_TYPE_STR, UL &Server_Pass, UL "opensource" },
    { "server_port", VAR_TYPE_INT, UL &Server_Port, 8888 },
    { "stat_click", VAR_TYPE_INT, UL &Stat_Click, 60 },
    { "strict_channels", VAR_TYPE_BOOL, OPTION_STRICT_CHANNELS, 0 },
    { "server_queue_length", VAR_TYPE_INT, UL &Server_Queue_Length, 1048576 },
    { "client_queue_length", VAR_TYPE_INT, UL &Client_Queue_Length, 102400 },
    { "max_results", VAR_TYPE_INT, UL &Max_Search_Results, 100 },
    { "compression_level", VAR_TYPE_INT, UL &Compression_Level, 1 },
    { "max_shared", VAR_TYPE_INT, UL &Max_Shared, 5000 },
    { "max_connections", VAR_TYPE_INT, UL &Max_Connections, FD_SETSIZE },
    { "nick_expire", VAR_TYPE_INT, UL &Nick_Expire, 7776000 /* 90 days */ },
    { "check_expire", VAR_TYPE_INT, UL &Check_Expire, 86400 /* 1 day */ },
    { "listen_addr", VAR_TYPE_STR, UL &Listen_Addr, UL "0.0.0.0" },
    { "max_browse_result", VAR_TYPE_INT, UL &Max_Browse_Result, 500 },
    { "collect_interval", VAR_TYPE_INT, UL &Collect_Interval, 300 },
#ifndef WIN32
    { "uid", VAR_TYPE_INT, UL &Uid, -1 },
    { "gid", VAR_TYPE_INT, UL &Gid, -1 },
    { "connection_hard_limit", VAR_TYPE_INT, UL &Connection_Hard_Limit, FD_SETSIZE },
    { "max_data_size", VAR_TYPE_INT, UL &Max_Data_Size, -1 },
    { "max_rss_size", VAR_TYPE_INT, UL &Max_Rss_Size, -1 },
#endif
    { "max_nick_length", VAR_TYPE_INT, UL &Max_Nick_Length, 32 },
    { "user_db_path", VAR_TYPE_STR, UL &User_Db_Path, UL SHAREDIR "/users" },
    { "server_db_path", VAR_TYPE_STR, UL &Server_Db_Path, UL SHAREDIR "/servers" },
    { "user_db_interval", VAR_TYPE_INT, UL &User_Db_Interval, 1800 },
    { "channel_limit", VAR_TYPE_INT, UL &Channel_Limit, 200 },
    { "login_timeout",	VAR_TYPE_INT, UL &Login_Timeout, 60 },
    { "max_command_length", VAR_TYPE_INT, UL &Max_Command_Length, 2048 }
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
	while (ISSPACE (*ptr))
	    ptr++;
	if (*ptr == '#' || *ptr == 0)
	    continue;
	val = strchr (ptr, ' ');
	if (val)
	{
	    *val++ = 0;
	    while (ISSPACE (*val))
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

    (void) tag;
    (void) len;
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

/* 800 [ :<user> ] <var>
   reset `var' to its default value */
HANDLER (server_reconfig)
{
    int i;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("server_reconfig");
    ASSERT (validate_user (con->user));
    if (con->user->level < LEVEL_ELITE)
    {
	permission_denied (con);
	return;
    }
    for (i = 0; i < Vars_Size; i++)
	if (!strcmp (pkt, Vars[i].name))
	{
	    if (Vars[i].def)
	    {
		if (Vars[i].type == VAR_TYPE_STR)
		    set_str_var (&Vars[i], (char*) Vars[i].def);
		else if (Vars[i].type == VAR_TYPE_INT)
		    set_int_var (&Vars[i], Vars[i].def);
	    }
	    else
	    {
		send_cmd (con, MSG_SERVER_NOSUCH, "no default value for %s",
		    pkt);
	    }
	    return;
	}
    send_cmd (con, MSG_SERVER_NOSUCH, "no such variable %s", pkt);
}
