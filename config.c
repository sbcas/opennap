/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <limits.h>
#include "opennap.h"
#include "debug.h"

typedef enum
{
    VAR_TYPE_INT,
    VAR_TYPE_STR,
    VAR_TYPE_BOOL,
    VAR_TYPE_LIST
}
VAR_TYPE;

struct config
{
    char *name;
    VAR_TYPE type;
    unsigned long val;
    unsigned long def;		/* default value */
};

#define UL (unsigned long)

static struct config Vars[] = {
    {"client_queue_length", VAR_TYPE_INT, UL & Client_Queue_Length, 102400},
    {"max_results", VAR_TYPE_INT, UL & Max_Search_Results, 100},
    {"max_user_channels", VAR_TYPE_INT, UL & Max_User_Channels, 5},
    {"server_name", VAR_TYPE_STR, UL & Server_Name, 0},
    {"server_password", VAR_TYPE_STR, UL & Server_Pass, UL "opensource"},
    {"server_ports", VAR_TYPE_LIST, UL & Server_Ports, UL "8888"},
    {"server_queue_length", VAR_TYPE_INT, UL & Server_Queue_Length, 1048576},
    {"stat_click", VAR_TYPE_INT, UL & Stat_Click, 60},
    {"strict_channels", VAR_TYPE_BOOL, ON_STRICT_CHANNELS, 0},
    {"max_shared", VAR_TYPE_INT, UL & Max_Shared, 5000},
    {"max_connections", VAR_TYPE_INT, UL & Max_Connections, FD_SETSIZE},
    {"nick_expire", VAR_TYPE_INT, UL & Nick_Expire, 2678400 /* 31 days */ },
    {"listen_addr", VAR_TYPE_STR, UL & Listen_Addr, UL "0.0.0.0"},
    {"max_browse_result", VAR_TYPE_INT, UL & Max_Browse_Result, 500},
    {"collect_interval", VAR_TYPE_INT, UL & Collect_Interval, 300},
    {"compression_level", VAR_TYPE_INT, UL & Compression_Level, 1},
#ifndef WIN32
    {"uid", VAR_TYPE_INT, UL & Uid, -1},
    {"gid", VAR_TYPE_INT, UL & Gid, -1},

    {"connection_hard_limit", VAR_TYPE_INT, UL & Connection_Hard_Limit,
     FD_SETSIZE},
    {"max_data_size", VAR_TYPE_INT, UL & Max_Data_Size, -1},
    {"max_rss_size", VAR_TYPE_INT, UL & Max_Rss_Size, -1},
    {"lock_memory", VAR_TYPE_BOOL, ON_LOCK_MEMORY, 0},
#endif
    {"max_nick_length", VAR_TYPE_INT, UL & Max_Nick_Length, 19},
    {"user_db_interval", VAR_TYPE_INT, UL & User_Db_Interval, 1800},
    {"channel_limit", VAR_TYPE_INT, UL & Channel_Limit, 200},
    {"login_timeout", VAR_TYPE_INT, UL & Login_Timeout, 60},
    {"max_command_length", VAR_TYPE_INT, UL & Max_Command_Length, 2048},
    {"config_dir", VAR_TYPE_STR, UL & Config_Dir, UL SHAREDIR},
    {"registered_only", VAR_TYPE_BOOL, ON_REGISTERED_ONLY, 0},
    {"auto_register", VAR_TYPE_BOOL, ON_AUTO_REGISTER, 0},
    {"max_channel_length", VAR_TYPE_INT, UL & Max_Channel_Length, 32},
    {"max_ignore",VAR_TYPE_INT,UL&Max_Ignore,32},
    {"max_hotlist",VAR_TYPE_INT,UL&Max_Hotlist,32},
    {"max_topic",VAR_TYPE_INT,UL&Max_Topic,64},
    {"max_client_string",VAR_TYPE_INT,UL&Max_Client_String,32},
    {"max_reason",VAR_TYPE_INT,UL&Max_Reason,64},
    {"max_clones",VAR_TYPE_INT,UL&Max_Clones,0},
    {"search_timeout",VAR_TYPE_INT,UL&Search_Timeout,180},
    {"stats_port",VAR_TYPE_INT,UL&Stats_Port,8889},
    {"eject_when_full",VAR_TYPE_BOOL,ON_EJECT_WHEN_FULL,0},
};

static int Vars_Size = sizeof (Vars) / sizeof (struct config);

static void
set_int_var (struct config *v, int val)
{
    ASSERT (v->type == VAR_TYPE_INT);
    *(int *) v->val = val;
}

static void
set_str_var (struct config *v, const char *s)
{
    char **ptr;

    ASSERT (v->type == VAR_TYPE_STR);
    ptr = (char **) v->val;
    if (*ptr)
	FREE (*ptr);
    *ptr = STRDUP (s);
}

static void
set_list_var (struct config *v, const char *s)
{
    int ac, i;
    char *av[32];
    LIST *tmpList, *list = 0;


    ASSERT (v->type == VAR_TYPE_LIST);
    strncpy (Buf, s, sizeof (Buf) - 1);
    Buf[sizeof (Buf) - 1] = 0;
    ac = split_line (av, FIELDS (av), Buf);
    for (i = 0; i < ac; i++)
    {
	tmpList = CALLOC (1, sizeof (LIST));
	tmpList->data = STRDUP (av[i]);
	tmpList->next = list;
	list = tmpList;
    }
    list_free (*(LIST **) v->val, free_pointer);
    *(LIST **) v->val = list;
}

static void
set_bool_var (struct config *v, int on)
{
    ASSERT (v->type == VAR_TYPE_BOOL);
    if (on)
	Server_Flags |= v->val;
    else
	Server_Flags &= ~v->val;
}

static int
set_var (const char *var, const char *val)
{
    int i, n;
    char *ptr;

    for (i = 0; i < Vars_Size; i++)
    {
	if (!strcmp (Vars[i].name, var))
	{
	    if (Vars[i].type == VAR_TYPE_INT)
	    {
		n = strtol (val, &ptr, 10);
		if (*ptr)
		{
		    log ("set_var(): invalid integer value: %s", val);
		    return -1;
		}
		set_int_var (&Vars[i], n);
	    }
	    else if (Vars[i].type == VAR_TYPE_STR)
		set_str_var (&Vars[i], val);
	    else if (Vars[i].type == VAR_TYPE_BOOL)
	    {
		if (!strcasecmp ("yes", val) || !strcasecmp ("on", val))
		    n = 1;
		else if (!strcasecmp ("no", val) || !strcasecmp ("off", val))
		    n = 0;
		else
		{
		    n = strtol (val, &ptr, 10);
		    if (*ptr)
		    {
			log ("set_var(): invalid boolean value: %s", val);
			return -1;
		    }
		}
		set_bool_var (&Vars[i], n);
	    }
	    else if (Vars[i].type == VAR_TYPE_LIST)
		set_list_var (&Vars[i], val);
	    else
	    {
		ASSERT (0);
	    }
	    return 0;
	}
    }
    log ("set_var(): unknown variable %s", var);
    return -1;
}

void
config (const char *path)
{
    FILE *f;
    char *ptr, *val;
    int line = 0;

    if ((f = fopen (path, "r")))
    {
	log("config(): reading %s", path);
	while (fgets (Buf, sizeof (Buf), f))
	{
	    /* strip trailing whitespace */
	    ptr = Buf + strlen (Buf);
	    while (ptr > Buf && ISSPACE (*(ptr - 1)))
		ptr--;
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
		log ("config(): error in %s, line %d: %s=%s", path, line, ptr,
		     val);
	}
	fclose (f);
    }
}

static void
query_var(CONNECTION *con, struct config *v)
{
    if (v->type == VAR_TYPE_INT)
	send_cmd (con, MSG_SERVER_NOSUCH, "%s = %d", v->name, *(int *) v->val);
    else if (v->type == VAR_TYPE_BOOL)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "%s = %s", v->name,
		(Server_Flags & v->val) ? "on" : "off");
    }
    else if (v->type == VAR_TYPE_LIST)
    {
	char buf[1024];
	LIST *tmpList = 0;

	buf[0] = 0;
	for (tmpList = *(LIST **) v->val; tmpList; tmpList = tmpList->next)
	    snprintf (buf + strlen (buf), sizeof (buf) - strlen (buf),
		    "%s ", (char *) tmpList->data);
	send_cmd (con, MSG_SERVER_NOSUCH, "%s = %s", v->name, buf);
    }
    else
    {
	ASSERT (v->type == VAR_TYPE_STR);
	send_cmd (con, MSG_SERVER_NOSUCH, "%s = %s", v->name, *(char **) v->val);
    }
}

/* 810 [ <var> [ <value> ] ] */
HANDLER (server_config)
{
    char *av[2];
    int ac;

    (void) tag;
    (void) len;
    ASSERT (validate_connection (con));
    CHECK_USER_CLASS ("server_config");

    /* allow mods+ to query the config values, only elites can set them */
    if (con->user->level < LEVEL_MODERATOR)
    {
	permission_denied (con);
	return;
    }

    ac=split_line(av,FIELDS(av),pkt);
    if(ac==0)
    {
	/* user requests all config variables */
	for(ac=0;ac<Vars_Size;ac++)
	    query_var(con, &Vars[ac]);
    }
    else if(ac==1)
    {
	/* user requests the value of a specific variable */
	for(ac=0;ac<Vars_Size;ac++)
	    if(!strcasecmp(av[0],Vars[ac].name))
	    {
		query_var(con, &Vars[ac]);
		return;
	    }
	send_cmd (con, MSG_SERVER_NOSUCH, "no such variable %s", pkt);
    }
    else
    {
	if(con->user->level < LEVEL_ELITE)
	{
	    permission_denied(con);
	    return;
	}
	/* user changes the value of a specific variable */
	if (set_var (av[0], av[1]) != 0)
	{
	    send_cmd (con, MSG_SERVER_NOSUCH, "error setting variable %s",
		    av[0]);
	}
    }
}

void
free_config (void)
{
    int i;

    for (i = 0; i < Vars_Size; i++)
	if (Vars[i].type == VAR_TYPE_STR && *(char **) Vars[i].val)
	    FREE (*(char **) Vars[i].val);
	else if (Vars[i].type == VAR_TYPE_LIST)
	    list_free (*(LIST **) Vars[i].val, free_pointer);
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
		set_str_var (&Vars[i], (char *) Vars[i].def);
	    else if (Vars[i].type == VAR_TYPE_INT)
		set_int_var (&Vars[i], Vars[i].def);
	    else if (Vars[i].type == VAR_TYPE_LIST)
		set_list_var (&Vars[i], (char *) Vars[i].def);
	    else if (Vars[i].type == VAR_TYPE_BOOL)
		set_bool_var (&Vars[i], Vars[i].def);
#if DEBUG
	    else
		ASSERT (0);
#endif
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
		    set_str_var (&Vars[i], (char *) Vars[i].def);
		else if (Vars[i].type == VAR_TYPE_INT)
		    set_int_var (&Vars[i], Vars[i].def);
		else if (Vars[i].type == VAR_TYPE_BOOL)
		    set_bool_var (&Vars[i], Vars[i].def);
		else if (Vars[i].type == VAR_TYPE_BOOL)
		    set_list_var (&Vars[i], (char *) Vars[i].def);
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

/* 10116 [ :user ] [server]
 * reload configuration file
 */
HANDLER (rehash)
{
    USER *sender;

    (void)len;
    if(pop_user(con,&pkt,&sender))
	return;
    if(sender->level < LEVEL_ELITE)
    {
	permission_denied(con);
	return;
    }
    notify_mods(SERVERLOG_MODE,"%s reloaded configuration on %s",
	    sender->nick, pkt && *pkt ? pkt : Server_Name);
    if(!pkt || !*pkt || !strcasecmp(Server_Name, pkt))
    {
	char path[_POSIX_PATH_MAX];

	snprintf(path,sizeof(path),"%s/config",Config_Dir);
	config(path);
	/* since the motd is stored in memory, reread it */
	motd_close();
	motd_init();
	/* reread filter file */
	free_filter();
	load_filter();
    }
    /* pass the message even if this is the server we are reloading so that
     * everyone sees the message
     */
    pass_message_args(con,tag,":%s %s",sender->nick,
	    pkt && *pkt ? pkt : Server_Name);
}
