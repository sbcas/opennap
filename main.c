/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#ifdef WIN32
#include <windows.h>
#include <winsock.h>
#endif /* WIN32 */
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#ifndef WIN32
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/time.h>
#endif /* !WIN32 */
#include "opennap.h"
#include "debug.h"

/*
** Global Variables
*/

char *Motd_Path = 0;
char *Listen_Addr = 0;
char *Server_Name = 0;
char *Server_Pass = 0;
unsigned int Server_Ip = 0;
unsigned int Server_Flags = 0;
int Max_User_Channels;		/* default, can be changed in config */
int Stat_Click;			/* interval (in seconds) to send server stats */
int Server_Port;		/* which port to listen on for connections */
int Server_Queue_Length;
int Client_Queue_Length;
int Max_Search_Results;
int Compression_Level;
int Max_Shared;
int Max_Connections;
int Nick_Expire;
int Check_Expire;
int Max_Browse_Result;
unsigned int Interface = INADDR_ANY;
time_t Server_Start;		/* time at which the server was started */
int Collect_Interval;
unsigned int Bytes_In = 0;
unsigned int Bytes_Out = 0;
int User_Db_Interval;		/* how often to save the user database */
int Channel_Limit;
int Login_Timeout;

#ifndef WIN32
int Uid;
int Gid;
int Connection_Hard_Limit;
int Max_Data_Size;
int Max_Rss_Size;
#endif
time_t Current_Time;
int Max_Nick_Length;
char *User_Db_Path;
char *Server_Db_Path;

/* bans on ip addresses / users */
LIST *Bans = 0;

/* local clients (can be users or servers) */
CONNECTION **Clients = NULL;
int Num_Clients = 0;
int Max_Clients = 0;

/* global users list */
HASH *Users;

/* global file list */
HASH *File_Table;

/* global hash list */
HASH *MD5;

/* local server list.  NOTE that this contains pointers into the Clients
   list to speed up server-server message passing */
LIST *Servers = 0;

/* list of all servers in the cluster */
LIST *Server_Links = 0;

int Local_Files = 0;	/* number of files shared by local users */
int Num_Files = 0;
int Num_Gigs = 0;		/* in kB */
int SigCaught = 0;
char Buf[2048];			/* global scratch buffer */

/* global channel list */
HASH *Channels;

/* global hotlist */
HASH *Hotlist;

#define BACKLOG 50

static time_t Last_Click = 0;

static void
update_stats (void)
{
    int i, l;
    int numServers = list_count (Servers);
    time_t delta;

    strcpy (Buf, ctime (&Current_Time));
    Buf[strlen (Buf) - 1] = 0;
    log ("update_stats(): current time is %s", Buf);
    log ("update_stats(): library is %d KB (%d GB), %d files, %d users",
	 Num_Gigs, Num_Gigs / (1024 * 1024), Num_Files, Users->dbsize);
    log ("update_stats(): %d local clients, %d linked servers",
	 Num_Clients - numServers, numServers);
    log ("update_stats(): %s local files", Local_Files);
    log ("update_stats(): File_Table contains %d entries", File_Table->dbsize);
    delta = Current_Time - Last_Click;
    log ("update_stats(): %.2f kbytes/sec in, %.2f kbytes/sec out",
	(float) Bytes_In / 1024. / delta, (float) Bytes_Out / 1024. / delta);
    Bytes_In = 0;
    Bytes_Out = 0;
    Last_Click = Current_Time;

    /* since we send the same data to many people, optimize by forming
       the message once then writing it out */
    snprintf (Buf + 4, sizeof (Buf) - 4, "%d %d %d", Users->dbsize, Num_Files,
	      Num_Gigs / (1024 * 1024));
    set_tag (Buf, MSG_SERVER_STATS);
    l = strlen (Buf + 4);
    set_len (Buf, l);
    l += 4;
    for (i = 0; i < Max_Clients; i++)
    {
	if (Clients[i] && ISUSER (Clients[i]))
	    queue_data (Clients[i], Buf, l);
    }
}

/* accept all pending connections */
static void
accept_connection (int s)
{
    CONNECTION *cli;
    socklen_t sinsize;
    struct sockaddr_in sin;
    int f;

    for(;;)
    {
	sinsize = sizeof (sin);
	if ((f = accept (s, (struct sockaddr *) &sin, &sinsize)) < 0)
	{
	    if (N_ERRNO != EWOULDBLOCK)
		nlogerr ("accept_connection", "accept");
	    return;
	}
	if ((cli = new_connection ()) == 0)
	{
	    CLOSE (f);
	    return;
	}
	cli->fd = f;
	/* if we have a local connection, use the external
	   interface so others can download from them */
	if (sin.sin_addr.s_addr == inet_addr ("127.0.0.1"))
	{
	    log ("accept_connection(): connected via loopback, using external ip");
	    cli->ip = Server_Ip;
	    cli->host = STRDUP (Server_Name);
	    if (!cli->host)
	    {
		OUTOFMEMORY ("accept_connection");
		goto error;
	    }
	}
	else
	{
	    cli->ip = sin.sin_addr.s_addr;
	    cli->host = STRDUP (inet_ntoa (sin.sin_addr));
	    if (!cli->host)
	    {
		OUTOFMEMORY ("accept_connection");
		goto error;
	    }
	}
	cli->port = ntohs (sin.sin_port);
	cli->class = CLASS_UNKNOWN;
	cli->timer = Current_Time;	/* set a login timer */
	if (add_client (cli))
	    return;
	set_nonblocking (f);
	set_keepalive (f, 1);	/* enable tcp keepalive messages */
	check_ban (cli, cli->host, BAN_IP);
    }
    /* not reached */
    ASSERT (0);
    return;
error:
    CLOSE (f);
    if (cli->host)
	FREE (cli->host);
    FREE (cli);
}

static void
report_stats (int fd)
{
    int n;
    struct sockaddr_in sin;
    socklen_t sinsize = sizeof (sin);
    float loadavg = 0;

    n = accept (fd, (struct sockaddr *) &sin, &sinsize);
    if (n == -1)
    {
	logerr ("report_stats", "accept");
	return;
    }
    log ("report_stats(): connection from %s:%d", inet_ntoa (sin.sin_addr),
	 htons (sin.sin_port));
#ifdef linux
    {
	FILE *f = fopen ("/proc/loadavg", "r");

	if (f)
	{
	    fscanf (f, "%f", &loadavg);
	    fclose (f);
	}
	else
	{
	    log ("report_stats(): /proc/loadavg: %s (errno %d)",
		 strerror (errno), errno);
	}
    }
#endif /* linux */
    snprintf (Buf, sizeof (Buf), "%d %d %.2f %.0f 0\n", Users->dbsize,
	      Num_Files, loadavg, ((double) Num_Gigs) * 1024.0);
    WRITE (n, Buf, strlen (Buf));
    CLOSE (n);
}

static void
usage (void)
{
    fprintf (stderr,
	     "usage: %s [ -hsv ] [ -c FILE ] [ -p PORT ] [ -l IP ]\n",
	     PACKAGE);
    fprintf (stderr, "  -c FILE	read config from FILE (default: %s/config\n",
	     SHAREDIR);
    fputs ("  -h		print this help message\n", stderr);
    fputs
	("  -l IP		listen only on IP instead of all interfaces\n",
	 stderr);
    fputs ("  -p PORT	listen on PORT for connections (default: 8888)\n",
	   stderr);
    fputs
	("  -s		channels may only be created by privileged users\n",
	 stderr);
    fputs ("  -v		display version information\n", stderr);
    exit (0);
}

static void
version (void)
{
    fprintf (stderr, "%s %s\n", PACKAGE, VERSION);
    fprintf (stderr, "Copyright (C) 2000 drscholl@users.sourceforge.net\n");
    exit (0);
}

int
main (int argc, char **argv)
{
    int s;			/* server socket */
    int sp = -1;		/* stats port */
    int i;			/* generic counter */
    int numReady;		/* number of ready sockets */
    int port = 0, iface = INADDR_ANY, nolisten = 0;
    fd_set set, wset;
    struct timeval t;
    int maxfd;
    char *config_file = 0;

#ifdef WIN32
    WSADATA wsa;

    WSAStartup (MAKEWORD (1, 1), &wsa);
#endif /* !WIN32 */

    /* printf("%d\n", sizeof(DATUM)); */

    while ((i = getopt (argc, argv, "c:hl:p:vD")) != -1)
    {
	switch (i)
	{
	case 'D':
	    nolisten++;
	    break;
	case 'c':
	    config_file = optarg;
	    break;
	case 'l':
	    iface = inet_addr (optarg);
	    break;
	case 'p':
	    port = atoi (optarg);
	    break;
	case 's':
	    Server_Flags |= OPTION_STRICT_CHANNELS;
	    break;
	case 'v':
	    version ();
	    break;
	default:
	    usage ();
	}
    }

    if (init_server (config_file))
	exit (1);

    /* if the interface was specified on the command line, override the
       value from the config file */
    if (iface != INADDR_ANY)
	Interface = iface;
    else
	Interface = inet_addr (Listen_Addr);

    Server_Ip = Interface;

    if (Server_Ip == INADDR_ANY)
    {
	/* need to get the ip address of the external interface so that
	   locally connected users can trasnfer files with remotely
	   connected users.  the server will see local user as coming from
	   127.0.0.1. */
	Server_Ip = lookup_ip (Server_Name);
    }

    /* if a port was specified on the command line, override the value
       specified in the config file */
    if (port != 0)
	Server_Port = port;

    /* create the incoming connections socket */
    s = new_tcp_socket ();
    if (s < 0)
	exit (1);

    i = 1;
    if (setsockopt (s, SOL_SOCKET, SO_REUSEADDR, SOCKOPTCAST & i, sizeof (i))
	!= 0)
    {
	perror ("setsockopt");
	exit (1);
    }

    if (set_nonblocking (s))
	exit (1);

    if (bind_interface (s, Interface, Server_Port) == -1)
	exit (1);

    if (listen (s, BACKLOG) < 0)
    {
	perror ("listen");
	exit (1);
    }

    log ("listening on %s port %d", my_ntoa (Interface), Server_Port);

    if (!nolisten)
    {
	/* listen on port 8889 for stats reporting */
	if ((sp = new_tcp_socket ()) == -1)
	    exit (1);
	if (bind_interface (sp, Interface, 8889))
	    exit (1);
	if (listen (sp, BACKLOG))
	{
	    perror ("listen");
	    exit (1);
	}
    }

    /* initialize the random number generator */
    init_random ();

    /* schedule periodic events */
    add_timer (Collect_Interval, -1, (timer_cb_t) fdb_garbage_collect,
	       File_Table);
    add_timer (Collect_Interval, -1, (timer_cb_t) fdb_garbage_collect, MD5);
    add_timer (Stat_Click, -1, (timer_cb_t) update_stats, 0);
    add_timer (User_Db_Interval, -1, (timer_cb_t) userdb_dump, 0);

    /* initialize so we get the correct delta for the first call to
       update_stats() */
    Last_Click = Current_Time;

    /* main event loop */
    while (!SigCaught)
    {
	Current_Time = time (0);

	FD_ZERO (&set);
	FD_ZERO (&wset);
	maxfd = s;
	FD_SET (s, &set);
	if (!nolisten)
	{
	    FD_SET (sp, &set);
	    if (sp > maxfd)
		maxfd = sp;
	}

	for (i = 0; i < Max_Clients; i++)
	{
	    if (Clients[i])
	    {
		FD_SET (Clients[i]->fd, &set);
		if (Clients[i]->fd > maxfd)
		    maxfd = Clients[i]->fd;
		/* check sockets for writing */
		if (Clients[i]->connecting || Clients[i]->sendbuf ||
		     (ISSERVER (Clients[i]) && Clients[i]->sopt->outbuf))
		    FD_SET (Clients[i]->fd, &wset);
	    }
	}

	t.tv_sec = next_timer ();
	t.tv_usec = 0;
	if ((numReady = select (maxfd + 1, &set, &wset, NULL, &t)) < 0)
	{
	    perror ("main(): select");
	    continue;
	}

	/* process incoming requests */
	for (i = 0; !SigCaught && i < Max_Clients; i++)
	    if (Clients[i] && FD_ISSET (Clients[i]->fd, &set))
		handle_connection (Clients[i]);

	if (SigCaught)
	    break;

	/* write out data and reap dead client connections */
	for (i = 0; !SigCaught && i < Max_Clients; i++)
	{
	    if (Clients[i])
	    {
		if (FD_ISSET (Clients[i]->fd, &wset))
		{
		    /* check for return from nonblocking connect() call */
		    if (Clients[i]->connecting)
			complete_connect (Clients[i]);
		    else if (send_queued_data (Clients[i]) == -1)
			Clients[i]->destroy = 1;
		}
		/* kill idle conenctions */
		else if (Clients[i]->class == CLASS_UNKNOWN &&
			 Current_Time - Clients[i]->timer >= Login_Timeout)
		{
		    log("main(): login timeout for %s", Clients[i]->host);
		    Clients[i]->destroy = 1;
		}

		if (Clients[i]->destroy)
		{
		    send_queued_data (Clients[i]);	/* flush */
		    remove_connection (Clients[i]);
		}
	    }
	}

	if (sp != -1 && FD_ISSET (sp, &set))
	    report_stats (sp);

	/* check for new incoming connections. handle this last so that
	   we don't screw up the loops above.  this is crucial when using
	   poll() because Max_Clients could increase to something greater
	   than ufdsize-2 causing us to read off the end of the array */
	if (FD_ISSET (s, &set))
	    accept_connection (s);

	/* execute any pending events now */
	exec_timers (Current_Time);
    }

    if (SigCaught)
	log ("caught signal");

    log ("shutting down");

    /* disallow incoming connections */
    CLOSE (s);
    if (sp != -1)
	CLOSE (sp);

    /* write out the user database */
    userdb_dump ();

    save_bans ();

    /* close all client connections */
    for (i = 0; i < Max_Clients; i++)
	if (Clients[i])
	    remove_connection (Clients[i]);

    /* only clean up memory if we are in debug mode, its kind of pointless
       otherwise */
#if DEBUG
    /* clean up */
    if (Clients)
	FREE (Clients);

    if (Servers)
	FREE (Servers);

    free_hash (File_Table);
    free_hash (MD5);
    free_hash (Users);
    free_hash (Channels);
    free_hash (Hotlist);
    free_hash (User_Db);
    free_timers ();

    list_free (Bans, (list_destroy_t) free_ban);

    /* free up memory associated with global configuration variables */
    free_config ();

    /* this displays a list of leaked memory.  pay attention to this. */
    CLEANUP ();
#endif

#ifdef WIN32
    WSACleanup ();
#endif

    exit (0);
}
