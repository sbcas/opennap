/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#ifndef WIN32
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>
#include <netdb.h>
#include <limits.h>
#if HAVE_MLOCKALL
#include <sys/mman.h>
#endif /* HAVE_MLOCKALL */
#endif /* !WIN32 */
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef __EMX__
#include <stdlib.h>
#define _POSIX_PATH_MAX _MAX_PATH
#endif /* __EMX__ */
#include "opennap.h"
#include "debug.h"

static void
lookup_hostname (void)
{
    struct hostent *he;

    /* get our canonical host name */
    gethostname (Buf, sizeof (Buf));
    he = gethostbyname (Buf);
    if (he)
	Server_Name = STRDUP (he->h_name);
    else
    {
	log ("lookup_hostname(): unable to find fqdn for %s", Buf);
	Server_Name = STRDUP (Buf);
    }
}

#ifndef WIN32
static void
sighandler (int sig)
{
    switch (sig)
    {
    case SIGINT:
    case SIGHUP:
    case SIGTERM:
	SigCaught = 1;
	break;
    case SIGUSR1:
	CLEANUP ();
    }
}
#endif

/* write the pid to a file so an external program can check to see if the
   process is still running. */
static void
dump_pid (void)
{
    FILE *f;
    char path[_POSIX_PATH_MAX];

    log ("dump_pid(): pid is %d", getpid ());
    snprintf (path, sizeof (path), "%s/pid", Config_Dir);
    f = fopen (path, "w");
    if (!f)
    {
	logerr ("dump_pid", path);
	return;
    }
    fprintf (f, "%d\n", getpid ());
    fclose (f);
}

int
init_server (const char *cf)
{
#ifndef WIN32
    struct sigaction sa;

    memset (&sa, 0, sizeof (sa));
    sa.sa_handler = sighandler;
    sigaction (SIGHUP, &sa, NULL);
    sigaction (SIGTERM, &sa, NULL);
    sigaction (SIGINT, &sa, NULL);
    sigaction (SIGPIPE, &sa, NULL);
#ifndef __EMX__
    sa.sa_flags = SA_RESTART;
#endif /* ! __EMX__ */
    sigaction (SIGUSR1, &sa, NULL);
#endif /* !WIN32 */

    Current_Time = time (0);

    Server_Start = Current_Time;

    /* load default configuration values */
    config_defaults ();

    /* load the config file */
    config (cf ? cf : SHAREDIR "/config");

    /* if running in daemon mode, reopen stdout as a log file */
    if (Server_Flags & ON_BACKGROUND)
    {
	char path[_POSIX_PATH_MAX];
	int fd;

	snprintf (path, sizeof (path), "%s/log", Config_Dir);
	fd = open (path, O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR);
	if (fd > 0)
	{
	    /* close stdout */
	    if (dup2 (fd, 1) == -1)
	    {
		logerr ("init_server", "dup2");
		return -1;
	    }
	    close (fd);
	}
	else
	{
	    logerr ("init_server", path);
	    return -1;
	}
    }

    log ("init_server(): version %s starting", VERSION);
    dump_pid ();

    /* if not defined in the config file, get the system name */
    if (!Server_Name)
	lookup_hostname ();

    /* open files before dropping dropping cap */
    if (userdb_init ())
    {
	log ("init_server(): userdb_init failed");
	return -1;
    }

    load_bans ();

#if !defined(WIN32) && !defined(__EMX__)
    if (set_max_connections (Connection_Hard_Limit))
	return -1;
    if (Max_Data_Size != -1 && set_data_size (Max_Data_Size))
	return -1;
    if (Max_Rss_Size != -1 && set_rss_size (Max_Rss_Size))
	return -1;
#if HAVE_MLOCKALL
    if (Server_Flags & ON_LOCK_MEMORY)
    {
	if (mlockall (MCL_CURRENT | MCL_FUTURE))
	    logerr ("init_server", "mlockall");
    }
#endif /* HAVE_MLOCKALL */

    if (getuid () == 0)
    {
	if (Uid == -1)
	{
	    /* default to user nobody */
	    struct passwd *pw;

	    pw = getpwnam ("nobody");
	    if (!pw)
	    {
		fputs ("ERROR: can't find user nobody to drop privileges\n",
		       stderr);
		return -1;
	    }
	    Uid = pw->pw_uid;
	}

	if (Gid == -1)
	{
	    /* default to group nobody */
	    struct group *gr;

	    gr = getgrnam ("nobody");
	    if (!gr)
	    {
		fputs ("ERROR: can't find group nobody to drop privileges\n",
		       stderr);
		return -1;
	    }
	    Gid = gr->gr_gid;
	}

	/* change to non-privileged mode */
	if (setgid (Gid))
	{
	    logerr ("init_server", "setgid");
	    return -1;
	}

	if (setuid (Uid))
	{
	    logerr ("init_server", "setuid");
	    return -1;
	}
    }
    log ("init_server(): running as user %d, group %d", getuid (), getgid ());
#endif /* !WIN32 */

    log ("init_server(): my hostname is %s", Server_Name);

    /* initialize hash tables.  the size of the hash table roughly cuts
       the max number of matches required to find any given entry by the same
       factor.  so a 256 entry hash table with 1024 entries will take rougly
       4 comparisons max to find any one entry.  we use prime numbers here
       because that gives the table a little better spread */
    Users = hash_init (521, (hash_destroy) free_user);
    Channels = hash_init (257, (hash_destroy) free_channel);
    Hotlist = hash_init (521, (hash_destroy) free_hotlist);
    File_Table = hash_init (2053, (hash_destroy) free_flist);
#if RESUME
    MD5 = hash_init (2053, (hash_destroy) free_flist);
#endif

    load_channels ();

    init_random ();

    return 0;
}
