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
#endif /* !WIN32 */
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
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
    }
}
#endif

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
#endif /* !WIN32 */

    Current_Time = time (0);

    log ("version %s starting", VERSION);

    Server_Start = Current_Time;

    /* load default configuration values */
    config_defaults ();
    lookup_hostname ();

    /* load the config file */
    config (cf ? cf : SHAREDIR "/config");

    /* open files before dropping dropping cap */
    if (userdb_init (User_Db_Path))
    {
	log ("init(): userdb_init failed");
	return -1;
    }

#if !defined(WIN32) && !defined(__EMX__)
    if (set_max_connections (Connection_Hard_Limit))
	return -1;
    if (Max_Data_Size != -1 && set_data_size (Max_Data_Size))
	return -1;
    if (Max_Rss_Size != -1 && set_rss_size (Max_Rss_Size))
	return -1;

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
	    perror ("setgid");
	    return -1;
	}

	if (setuid (Uid))
	{
	    perror ("setuid");
	    return -1;
	}
    }
    log ("running as user %d, group %d", getuid (), getgid ());
#endif /* !WIN32 */

    log ("my hostname is %s", Server_Name);

    /* initialize hash tables.  the size of the hash table roughly cuts
       the max number of matches required to find any given entry by the same
       factor.  so a 256 entry hash table with 1024 entries will take rougly
       4 comparisons max to find any one entry.  we use prime numbers here
       because that gives the table a little better spread */
    Users = hash_init (257, (hash_destroy) free_user);
    Channels = hash_init (257, (hash_destroy) free_channel);
    Hotlist = hash_init (257, (hash_destroy) free_hotlist);
    File_Table = hash_init (2053, (hash_destroy) free_flist);
    MD5 = hash_init (2053, (hash_destroy) free_flist);

    return 0;
}
