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
#ifndef WIN32
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#if HAVE_POLL
#include <sys/poll.h>
#else
/* use select() instead of poll() */
#include <sys/time.h>
#endif /* HAVE_POLL */
#endif /* !WIN32 */
#include "opennap.h"
#include "debug.h"

/*
** Global Variables
*/

char *Motd_Path = 0;
char *Db_User = 0;
char *Db_Pass = 0;
char *Db_Host = 0;
char *Db_Name = 0;
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
int Compression_Threshold;
int Max_Shared;
int Max_Connections;
int Nick_Expire;
int Check_Expire;
int Max_Browse_Result;
unsigned int Interface = INADDR_ANY;
time_t Server_Start;	/* time at which the server was started */
int Collect_Interval;
int Uid;
int Gid;
int Connection_Hard_Limit;

/* bans on ip addresses / users */
BAN **Ban = 0;
int Ban_Size = 0;

/* local clients (can be users or servers) */
CONNECTION **Clients = NULL;
int Num_Clients = 0;

/* global users list */
HASH *Users;

/* global file list */
HASH *File_Table;

/* global hash list */
HASH *MD5;

/* local server list.  NOTE that this contains pointers into the Clients
   list to speed up server-server message passing */
CONNECTION **Servers = NULL;
int Num_Servers = 0;

int Num_Files = 0;
int Num_Gigs = 0;		/* in kB */
int SigCaught = 0;
char Buf[2048];			/* global scratch buffer */

/* global channel list */
HASH *Channels;

/* global hotlist */
HASH *Hotlist;

#define BACKLOG 50

static void
update_stats (void)
{
    int i, l;
    time_t t;

    t = time (0);
    log ("update_stats(): current time is %s", ctime (&t));
    log
	("update_stats(): library is %d kilobytes (%d gigabytes), %d files, %d users",
	 Num_Gigs, Num_Gigs / (1024 * 1024), Num_Files, Users->dbsize);
    log ("update_stats: %d local clients, %d linked servers",
	 Num_Clients - Num_Servers, Num_Servers);

    /* since we send the same data to many people, optimize by forming
       the message once then writing it out */
    snprintf (Buf + 4, sizeof (Buf) - 4, "%d %d %d", Users->dbsize, Num_Files,
	      Num_Gigs / (1024 * 1024));
    set_tag (Buf, MSG_SERVER_STATS);
    l = strlen (Buf + 4);
    set_len (Buf, l);
    l += 4;

    for (i = 0; i < Num_Clients; i++)
    {
	if (Clients[i] && Clients[i]->class == CLASS_USER)
	    queue_data (Clients[i], Buf, l);
    }
}

static int
ip_glob_match (const char *pattern, const char *ip)
{
    int l;

    /* if `pattern' ends with a `.', we ban an entire subclass */
    l = strlen (pattern);
    ASSERT (l > 0);
    if (pattern[l - 1] == '.')
	return ((strncmp (pattern, ip, l) == 0));
    else
	return ((strcmp (pattern, ip) == 0));
}

static int
check_accept (CONNECTION * cli)
{
    int i;

    /* check for max connections */
    if (Num_Clients >= Max_Connections)
    {
	log
	    ("check_accept: maximum number of connections (%d) has been reached",
	     Max_Connections);
	send_cmd (cli, MSG_SERVER_ERROR,
		  "this server is full (%d local connections)", Num_Clients);
	return 0;
    }

    /* make sure this ip is not banned */
    for (i = 0; i < Ban_Size; i++)
    {
	if (Ban[i]->type == BAN_IP &&
	    ip_glob_match (Ban[i]->target, cli->host))
	{
	    /* TODO: this does not reach all mods, only the one on
	       this server */
	    log ("check_accept: connection attempt from banned ip %s (%s)",
		 cli->host, NONULL (Ban[i]->reason));
	    notify_mods ("Connection attempt from banned ip %s", cli->host);
	    send_cmd (cli, MSG_SERVER_ERROR,
		      "You are banned from this server (%s)",
		      NONULL (Ban[i]->reason));
	    return 0;
	}
    }

    return 1;
}

static void
accept_connection (int s)
{
    CONNECTION *cli;
    socklen_t sinsize;
    struct sockaddr_in sin;
    int f;

    sinsize = sizeof (sin);
    if ((f = accept (s, (struct sockaddr *) &sin, &sinsize)) < 0)
    {
	perror ("accept_connection(): accept");
	return;
    }

    cli = new_connection ();
    cli->fd = f;
    log ("accept_connection(): connection from %s, port %d",
	    inet_ntoa (sin.sin_addr), ntohs (sin.sin_port));
    /* if we have a local connection, use the external
       interface so others can download from them */
    if (sin.sin_addr.s_addr == inet_addr ("127.0.0.1"))
    {
	log ("accept_connection(): connected via loopback, using external ip");
	cli->ip = Server_Ip;
	cli->host = STRDUP (Server_Name);
    }
    else
    {
	cli->ip = sin.sin_addr.s_addr;
	cli->host = STRDUP (inet_ntoa (sin.sin_addr));
    }
    cli->port = ntohs (sin.sin_port);
    cli->class = CLASS_UNKNOWN;
    add_client (cli);

    set_nonblocking (f);
    set_keepalive (f, 1);	/* enable tcp keepalive messages */

    if (!check_accept (cli))
	cli->destroy = 1;
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
	log ("report_stats(): accept: %s (errno %d)", strerror (errno), errno);
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
    snprintf (Buf, sizeof (Buf), "%d %d %.2f %lu 0\n", Users->dbsize, Num_Files,
	    loadavg, (unsigned long) (Num_Gigs) * 1024);
    write (n, Buf, strlen (Buf));
    close (n);
}

static void
usage (void)
{
    fprintf (stderr,
	     "usage: %s [ -hsv ] [ -c FILE ] [ -p PORT ] [ -l IP ]\n", PACKAGE);
    fprintf (stderr, "  -c FILE	read config from FILE (default: %s/config\n",
	     SHAREDIR);
    fputs ("  -h		print this help message\n", stderr);
    fputs ("  -l IP	listen only on IP instead of all interfaces", stderr);
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

/* wrappers to make the code in main() much cleaner */
#if HAVE_POLL
#define READABLE(i) (ufd[i].revents & POLLIN)
#define WRITABLE(i) (ufd[i].revents & POLLOUT)
#define CHECKREAD(i) ufd[i].events |= POLLIN
#define CHECKWRITE(i) ufd[i].events |= POLLOUT
#else
#define READABLE(i) FD_ISSET(Clients[i]->fd, &set)
#define WRITABLE(i) FD_ISSET(Clients[i]->fd, &wset)
#define CHECKREAD(i) FD_SET(Clients[i]->fd, &set)
#define CHECKWRITE(i) FD_SET(Clients[i]->fd, &wset)
#endif /* HAVE_POLL */

int
main (int argc, char **argv)
{
    int s;			/* server socket */
    int i;			/* generic counter */
    int n;			/* number of ready sockets */
    int sp;			/* stats port */
    int f, pending = 0, port = 0, iface = INADDR_ANY;
#if HAVE_POLL
    struct pollfd *ufd = 0;
    int ufdsize = 0;		/* real number of pollfd structs allocated */
#else
    fd_set set, wset;
    struct timeval t;
    int maxfd;
#endif /* HAVE_POLL */
    char *config_file = 0;
    time_t next_update = 0;
    time_t next_collect = time (0) + Collect_Interval;	/* when to run garbage
							   collection */
#ifdef WIN32
    WSADATA wsa;

    WSAStartup (MAKEWORD (1, 1), &wsa);
#endif /* !WIN32 */

#ifndef WIN32
    while ((n = getopt (argc, argv, "c:hl:p:v")) != EOF)
    {
	switch (n)
	{
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
#endif /* !WIN32 */

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

    n = 1;
    if (setsockopt (s, SOL_SOCKET, SO_REUSEADDR, SOCKOPTCAST &n, sizeof (n)) != 0)
    {
	perror ("setsockopt");
	exit (1);
    }

    if (bind_interface (s, Interface, Server_Port) == -1)
	exit (1);

    if (listen (s, BACKLOG) < 0)
    {
	perror ("listen");
	exit (1);
    }

    log ("listening on %s port %d", my_ntoa (Interface), Server_Port);

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

#ifndef HAVE_DEV_RANDOM
    init_random ();
#endif /* !HAVE_DEV_RANDOM */

    /* main event loop */
    while (!SigCaught)
    {
#if HAVE_POLL
	/* ensure that we have enough pollfd structs.  add two extra for
	   the incoming connections port and the stats port */
	if (Num_Clients + 2 > ufdsize)
	{
	    ufd = REALLOC (ufd, sizeof (struct pollfd) * (Num_Clients + 2));
	    if (!ufd)
	    {
		log ("main(): OUT OF MEMORY");
		break; /* nothing to do here but shut down */
	    }
	    ufdsize = Num_Clients + 2;
	}
#else
	FD_ZERO (&set);
	FD_ZERO (&wset);
	maxfd = s;
	FD_SET (s, &set);
	FD_SET (sp, &set);
	if (sp > maxfd)
	    maxfd = sp;
#endif /* HAVE_POLL */

	for (n = 0, i = 0; i < Num_Clients; i++)
	{
	    /* several of the message handlers might cause connections to
	       disappear during the course of this loop, so we must check to
	       make sure this connection is still valid.  if its missing, we
	       shift down the array to fill the holes */
	    if (Clients[i])
	    {
		/* if there are holes, we shift down the upper structs
		   to fill them */
		if (i != n)
		{
		    Clients[n] = Clients[i];
		    Clients[n]->id = n;
		}
#if HAVE_POLL
		ufd[n].fd = Clients[n]->fd;
		ufd[n].events = 0;
#endif /* HAVE_POLL */

		n++;

		/* check sockets for writing */
		if ((Clients[i]->flags & FLAG_CONNECTING) ||
		    (Clients[i]->sendbuf ||
		     (Clients[i]->zip && Clients[i]->zip->outbuf)))
		    CHECKWRITE(i);

		/* always check for incoming data */
		CHECKREAD(i);

#ifndef HAVE_POLL
		if (Clients[i]->fd > maxfd)
		    maxfd = Clients[i]->fd;
#endif /* !HAVE_POLL */

		/* note if their is unprocessed data in the input
		   buffers so we dont block on select().  the incomplete
		   flag is checked here to avoid busy waiting when we really
		   do need more data from the client connection */
		if ((Clients[i]->incomplete == 0 && Clients[i]->recvbuf) ||
		    (Clients[i]->zip && Clients[i]->zip->inbuf))
		    pending++;
	    }
	}

	Num_Clients = n;	/* actual number of clients */

	/* if there is pending data in client queues, don't block on the
	   select call */
#if HAVE_POLL
	/* add entries for the incoming connections socket and stats socket */
	ufd[Num_Clients].fd = s;
	ufd[Num_Clients].events = POLLIN;
	ufd[Num_Clients+1].fd = sp;
	ufd[Num_Clients+1].events = POLLIN;

	if ((n = poll (ufd, Num_Clients + 2, pending ? 0 : Stat_Click * 1000)) < 0)
	{
	    perror ("poll");
	    continue;
	}
#else
	t.tv_sec = pending ? 0 : Stat_Click;
	t.tv_usec = 0;
	if ((n = select (maxfd + 1, &set, &wset, NULL, &t)) < 0)
	{
	    perror ("select");
	    continue;
	}
#endif /* HAVE_POLL */

	pending = 0;		/* reset */

	/* check for stats request.  NOTE: this _MUST_ come before the
	   check for new connections since Num_Clients will increase and
	   we will check the wrong pollfd struct */
#if HAVE_POLL
	if (ufd[Num_Clients+1].revents & POLLIN)
#else
	if (FD_ISSET (sp, &set))
#endif
	{
	    report_stats (sp);
	    n--;
	}

	/* check for new incoming connections */
#if HAVE_POLL
	if (ufd[Num_Clients].revents & POLLIN)
#else
	if (FD_ISSET (s, &set))
#endif
	{
	    accept_connection (s);
	    n--;
	}

	/* read incoming data into buffers, but don't process it */
	for (i = 0; !SigCaught && n > 0 && i < Num_Clients; i++)
	{
	    if ((Clients[i]->flags & FLAG_CONNECTING) && WRITABLE (i))
	    {
		complete_connect (Clients[i]);
		n--;	/* keep track of how many we've handled */
	    }
	    else if (READABLE (i))
	    {
		n--;	/* keep track of how many we've handled */
		f = buffer_read (Clients[i]->fd,
		    (Clients[i]->zip !=
		     0) ? &Clients[i]->zip->
		    inbuf : &Clients[i]->recvbuf);
		if (f <= 0)
		{
		    if (f == 0)
			log ("main(): EOF from %s", Clients[i]->host);
		    Clients[i]->destroy = 1;
		}
	    }
#if HAVE_POLL
	    /* when does this occur?  i would have thought POLLHUP
	       would be when the connection hangs up, but it still
	       sets POLLIN and read() returns 0 */
	    else if ((ufd[i].revents & (POLLHUP | POLLERR)) != 0)
	    {
		ASSERT ((ufd[i].revents & POLLHUP) == 0);
		ASSERT ((ufd[i].revents & POLLERR) == 0);
		Clients[i]->destroy = 1;
		n--;
	    }
#endif /* HAVE_POLL */
	}

	if (SigCaught)
	    break;

	/* handle client requests */
	for (i = 0; !SigCaught && i < Num_Clients; i++)
	{
	    /* if the connection is going to be shut down, don't process it */
	    if (!Clients[i]->destroy)
	    {
		/* if there is input pending, handle it now */
		if (Clients[i]->recvbuf ||
		    (Clients[i]->zip && Clients[i]->zip->inbuf))
		    handle_connection (Clients[i]);
	    }
	}

	if (SigCaught)
	    break;

	/* we should send the clients updated server stats every so often */
	if (next_update < time (0))
	{
	    update_stats ();
	    next_update = time (0) + Stat_Click;
	}

	/* write out data and reap dead client connections */
	for (i = 0; !SigCaught && i < Num_Clients; i++)
	{
	    if (Clients[i]->zip)
	    {
		/* server - strategy is call send_queued_data() if there
		   there is data to be compressed, or if the socket is
		   writable and there is some compressed output */
		if (Clients[i]->sendbuf
		    || (Clients[i]->zip->outbuf && WRITABLE (i)))
		{
		    if (send_queued_data (Clients[i]) == -1)
			Clients[i]->destroy = 1;
		}
	    }
	    /* client.  if there is output to send and either the socket is
	       writable or we're about to close the connection, send any
	       queued data */
	    else if (Clients[i]->sendbuf &&
		(WRITABLE (i) || Clients[i]->destroy))
	    {
		if (send_queued_data (Clients[i]) == -1)
		    Clients[i]->destroy = 1;
	    }

	    /* check to see if this connection should be shut down */
	    if (Clients[i]->destroy)
	    {
		/* should have flushed everything */
		ASSERT (Clients[i]->sendbuf == 0);
		log ("main(): closing connection for %s", Clients[i]->host);
		remove_connection (Clients[i]);
	    }
	}

	if (time (0) > next_collect)
	{
	    fdb_garbage_collect (File_Table);
	    fdb_garbage_collect (MD5);
	    next_collect = time(0) + Collect_Interval;
	}
    }

    if (SigCaught)
	log ("caught signal");

    log ("shutting down");

    /* disallow incoming connections */
    CLOSE (s);

    /* close all client connections */
    for (i = 0; i < Num_Clients; i++)
    {
	if (Clients[i])
	    remove_connection (Clients[i]);
    }

    close_db ();

    /* clean up */
#if HAVE_POLL
    if (ufd)
	FREE (ufd);
#endif /* HAVE_POLL */

    if (Clients)
	FREE (Clients);

    if (Servers)
	FREE (Servers);

    free_hash (File_Table);
    free_hash (MD5);
    free_hash (Users);
    free_hash (Channels);
    free_hash (Hotlist);

    for (i = 0; i < Ban_Size; i++)
	free_ban (Ban[i]);
    if (Ban)
	FREE (Ban);

    /* free up memory associated with global configuration variables */
    free_config ();

    /* this displays a list of leaked memory.  pay attention to this. */
    CLEANUP ();

#ifdef WIN32
    WSACleanup ();
#endif

    exit (0);
}
