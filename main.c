/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
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
char *Server_Name = 0;
char *Server_Pass = 0;
unsigned long Server_Flags = 0;
int Max_User_Channels;		/* default, can be changed in config */
int Stat_Click;			/* interval (in seconds) to send server stats */
int Server_Port;		/* which port to listen on for connections */

/* bans on ip addresses / users */
BAN **Ban = 0;
int Ban_Size = 0;

/* local clients (can be users or servers) */
CONNECTION **Clients = NULL;
int Num_Clients = 0;

/* global users list */
HASH *Users;

/* local server list.  NOTE that this contains pointers into the Clients
   list to speed up server-server message passing */
CONNECTION **Servers = NULL;
int Num_Servers = 0;

int Num_Files = 0;
int Num_Gigs = 0;		/* in kB */
int SigCaught = 0;
char Buf[1024];			/* global scratch buffer */

/* global channel list */
HASH *Channels;

/* global hotlist */
HASH *Hotlist;

#define BACKLOG 5

static void
sighandler (int sig)
{
    (void) sig;			/* unused */
    SigCaught = 1;
}

void
log (const char *fmt, ...)
{
    va_list ap;

    printf ("%s: ", PACKAGE);
    va_start (ap, fmt);
    vprintf (fmt, ap);
    va_end (ap);
    fputc ('\n', stdout);
}

HANDLER (server_stats)
{
    (void) pkt;
    send_cmd (con, MSG_SERVER_STATS, "%d %d %d", Users->dbsize, Num_Files,
	      Num_Gigs / (1024 * 1024));
}

typedef struct
{
    int message;
    void (*handler) (CONNECTION *, char *);
}
HANDLER;

/* this is the table of valid commands we accept from both users and servers */
static HANDLER Protocol[] = {
    { MSG_CLIENT_LOGIN, login }, /* 6 */
    { MSG_CLIENT_LOGIN_REGISTER, login }, /* 7 */
    { MSG_CLIENT_ADD_FILE, add_file }, /* 100 */
    { MSG_CLIENT_REMOVE_FILE, remove_file }, /* 102 */
    { MSG_CLIENT_SEARCH, search }, /* 200 */
    { MSG_CLIENT_PRIVMSG, privmsg }, /* 205 */
    { MSG_CLIENT_ADD_HOTLIST, add_hotlist }, /* 207 */
    { MSG_CLIENT_ADD_HOTLIST_SEQ, add_hotlist }, /* 208 */
    { MSG_CLIENT_BROWSE, browse }, /* 211 */
    { MSG_SERVER_STATS, server_stats }, /* 214 */
    { MSG_CLIENT_RESUME_REQUEST, resume }, /* 215 */
    { MSG_CLIENT_DOWNLOAD_START, download_start }, /* 218 */
    { MSG_CLIENT_DOWNLOAD_END, download_end }, /* 219 */
    { MSG_CLIENT_UPLOAD_START, upload_start }, /* 220 */
    { MSG_CLIENT_UPLOAD_END, upload_end }, /* 221 */
    { MSG_CLIENT_REMOVE_HOTLIST, remove_hotlist }, /* 303 */
    { MSG_CLIENT_DOWNLOAD_FIREWALL, download }, /* 500 */
    { MSG_CLIENT_WHOIS, whois },
    { MSG_CLIENT_JOIN, join },
    { MSG_CLIENT_PART, part },
    { MSG_CLIENT_PUBLIC, public },
    { MSG_SERVER_PUBLIC, public },
    { MSG_CLIENT_USERSPEED, user_speed }, /* 600 */
    { MSG_CLIENT_KILL, kill_user },
    { MSG_CLIENT_DOWNLOAD, download },
    { MSG_CLIENT_UPLOAD_OK, upload_ok },
    { MSG_SERVER_TOPIC, topic },
    { MSG_CLIENT_MUZZLE, muzzle },
    { MSG_CLIENT_UNMUZZLE, unmuzzle },
    { MSG_CLIENT_BAN, ban }, /* 612 */
    { MSG_CLIENT_UNBAN, unban }, /* 614 */
    { MSG_CLIENT_BANLIST, banlist }, /* 615 */
    { MSG_CLIENT_LIST_CHANNELS, list_channels }, /* 618 */
    { MSG_CLIENT_DATA_PORT_ERROR, data_port_error }, /* 626 */
    { MSG_CLIENT_WALLOP, wallop }, /* 627 */
    { MSG_CLIENT_ANNOUNCE, announce }, /* 628 */
    { MSG_CLIENT_SETUSERLEVEL, level },
    { MSG_CLIENT_PING, ping }, /* 751 */
    { MSG_CLIENT_PONG, pong }, /* 752 */
    { MSG_CLIENT_SERVER_CONFIG, server_config }, /* 810 */
    { MSG_CLIENT_NAMES_LIST, list_users }, /* 830 */

    /* non-standard messages */
    { MSG_CLIENT_QUIT, client_quit },
    { MSG_SERVER_LOGIN, server_login },
    { MSG_SERVER_LOGIN, server_login },
    { MSG_SERVER_LOGIN_ACK, server_login_ack },
    { MSG_SERVER_USER_IP, user_ip }, /* 10013 */
    { MSG_CLIENT_CONNECT, server_connect }, /* 10100 */
    { MSG_CLIENT_DISCONNECT, server_disconnect }, /* 10101 */
    { MSG_CLIENT_KILL_SERVER, kill_server }, /* 10110 */
    { MSG_CLIENT_REMOVE_SERVER, remove_server }, /* 10111 */
};
static int Protocol_Size = sizeof (Protocol) / sizeof (HANDLER);

static void
handle_connection (CONNECTION *con)
{
    int l;
    unsigned short len, tag;

    ASSERT (VALID (con));

    /* read the packet header */
    /* we loop here because read() will return less than we ask for if the
       data arrives in separate packets */
    while (con->recvbytes < 4)
    {
	l = read (con->fd, con->recvhdr + con->recvbytes, 4 - con->recvbytes);
	if (l == -1)
	{
	    if (errno == EAGAIN)
	    {
		/* no data waiting, wail until next call to try and read
		   the rest of the packet header */
		log ("handle_connection(): read %d bytes of header, waiting...",
			con->recvbytes);
		return;
	    }
	    log ("handle_connection(): %s (errno %d)", strerror (errno), errno);
	    remove_connection (con);
	    return;
	}
	else if (l == 0)
	{
	    /* the only circumstance under which we get returned
	       less than we asked for is EOF from the client */
	    log ("main(): EOF from %s", con->host);
	    remove_connection (con);
	    return;
	}
	con->recvbytes += l;
    }

    /* read the length and tag shorts from the packet */
    memcpy (&len, con->recvhdr, 2);
    memcpy (&tag, con->recvhdr + 2, 2);

#ifndef HAVE_DEV_RANDOM
    add_random_bytes (con->recvhdr, 4);
#endif /* !HAVE_DEV_RANDOM */

#if WORDS_BIGENDIAN
    /* need to convert to big endian */
    len = BSWAP16 (len);
    tag = BSWAP16 (tag);
#endif /* WORDS BIGENDIAN */

    /* make sure we don't buffer overflow */
    if (len > con->recvdatamax)
    {
	if (len > 512)
	{
	    /* if we receive a message with length longer than this, there
	       is probably something wrong, and we don't want to allocate
	       all of our memory */
	    log ("handle_connection(): %d byte message from %s", len, con->host);
	    remove_connection (con);
	    return;
	}
	con->recvdatamax = len + 1; /* allow for the trailing \0 we add */
	con->recvdata = REALLOC (con->recvdata, con->recvdatamax);
    }

    /* read the data portion of the message */
    /* we loop here because read() will return less than we ask for if the
       data arrives in separate packets */
    while (con->recvbytes - 4 < len)
    {
	l = read (con->fd, con->recvdata + con->recvbytes - 4, len - con->recvbytes + 4);
	if (l == -1)
	{
	    if (errno == EAGAIN)
	    {
		/* no data pending, wait until next round for more data to
		   come in */
		log ("handle_connection(): read %d of %d bytes from packet, waiting...",
			con->recvbytes - 4, len);
		return;
	    }
	    log ("handle_connection(): read error %d (%s) from %s", errno,
		 strerror (errno), con->host);
	    remove_connection (con);
	    return;
	}
	else if (l == 0)
	{
	    /* the only circumstance under which we get returned less
	       than we asked for is EOF from the client */
	    log ("handle_connection(): EOF from %s", con->host);
	    remove_connection (con);
	    return;
	}

#ifndef HAVE_DEV_RANDOM
    add_random_bytes (con->recvdata + con->recvbytes - 4, l);
#endif /* !HAVE_DEV_RANDOM */

	con->recvbytes += l;
    }

    /* reset to 0 since we got all of the data we desired.  `len' contains
       the lenght of the packet body */
    con->recvbytes = 0;

    /* require that the client register before doing anything else */
    if (con->class == CLASS_UNKNOWN &&
	(tag != MSG_CLIENT_LOGIN && tag != MSG_CLIENT_LOGIN_REGISTER &&
	 tag != MSG_CLIENT_REGISTER && tag != MSG_SERVER_LOGIN &&
	 tag != MSG_SERVER_LOGIN_ACK))
    {
	log ("main(): %s is not registered, closing connection",
	     con->host);
	remove_connection (con);
	return;
    }

    /* if we received this message from a peer server, pass it
       along to the other servers behind us.  the ONLY message we don't
       propogate is an ACK from a peer server that we've requested a link
       with */
    if (con->class == CLASS_SERVER && tag != MSG_SERVER_LOGIN_ACK)
	pass_message (con, con->recvdata, len);

    ASSERT (con->recvdata != 0);
    con->recvdata[len] = 0;		/* terminate the string */

    for (l = 0; l < Protocol_Size; l++)
    {
	if (Protocol[l].message == tag)
	{
	    ASSERT (Protocol[l].handler != 0);
	    /* note that we pass only the data part of the packet */
	    Protocol[l].handler (con, con->recvdata);
	    return;
	}
    }

    log ("main(): unknown message: tag=%d, length=%d, data=%s", tag, len,
	len ? con->recvdata : "(empty)");

    send_cmd (con, MSG_SERVER_NOSUCH, "unknown command code %d", tag);
}

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
	log ("unable to find fqdn for %s", Buf);
	Server_Name = STRDUP (Buf);
    }
    endhostent();
}

static void
update_stats (void)
{
    int i, l;

    log ("update_stats(): current library size is %d kilobytes (%d gigabytes)",
	    Num_Gigs, Num_Gigs / (1024 * 1024));

    /* since we send the same data to many people, optimize by forming
       the message once then writing it out */
    snprintf (Buf + 4, sizeof (Buf) - 4, "%d %d %d", Users->dbsize, Num_Files,
	Num_Gigs / (1024 * 1024));
    set_tag (Buf, MSG_SERVER_STATS);
    l = strlen (Buf + 4);
    set_len (Buf, l);
    l += 4;

    for(i=0;i<Num_Clients;i++)
    {
	if(Clients[i] && Clients[i]->class == CLASS_USER)
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

static void
usage (void)
{
    fprintf (stderr,
	     "usage: %s [ -hsv ] [ -c FILE ] [ -p PORT ] \n",
	     PACKAGE);
    fprintf (stderr, "  -c FILE	read config from FILE (default: %s/config\n", SHAREDIR);
    fputs ("  -h		print this help message\n", stderr);
    fputs ("  -p PORT	listen on PORT for connections (default: 8888)\n", stderr);
    fputs ("  -s		channels may only be created by privileged users\n", stderr);
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
    struct sockaddr_in sin;
    int s;			/* server socket */
    int i;			/* generic counter */
    int n;			/* number of ready sockets */
    int f;			/* new socket for incoming connection */
    int port = 0, maxfd;
    fd_set set;
    struct sigaction sa;
    char *config_file = 0;
    socklen_t sinsize;
    time_t next_update = 0;
    struct timeval t;

    while ((n = getopt (argc, argv, "c:hp:v")) != EOF)
    {
	switch (n)
	{
	case 'c':
	    config_file = optarg;
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
	case 'h':
	default:
	    usage ();
	}
    }

    log ("version %s starting", VERSION);

    /* load default configuration values */
    config_defaults ();
    lookup_hostname ();

    memset (&sa, 0, sizeof (sa));
    sa.sa_handler = sighandler;
    sigaction (SIGHUP, &sa, NULL);
    sigaction (SIGTERM, &sa, NULL);
    sigaction (SIGINT, &sa, NULL);

    /* load the config file */
    config (config_file ? config_file : SHAREDIR "/config");

    /* if a port was specified on the command line, override the value
       specified in the config file */
    if (port != 0)
	Server_Port = port;

    log ("my hostname is %s", Server_Name);

    /* initialize the connection to the SQL database server */
    if (init_db () != 0)
	exit (1);

    /* initialize user table */
    Users = hash_init (257, (hash_destroy) free_user);

    /* initialize channel table */
    Channels = hash_init (257, (hash_destroy) free_channel);

    /* initialize the hotlist lookup table */
    Hotlist = hash_init (257, (hash_destroy) free_hotlist);

    /* create the incoming connections socket */
    s = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0)
    {
	perror ("socket");
	exit (1);
    }

    n = 1;
    if(setsockopt (s, SOL_SOCKET, SO_REUSEADDR, &n, sizeof (n))!=0)
    {
	perror("setsockopt");
	exit(1);
    }

    memset (&sin, 0, sizeof (sin));
    sin.sin_port = htons (Server_Port);
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_family = AF_INET;
    if (bind (s, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
	perror ("bind");
	exit (1);
    }

    if (listen (s, BACKLOG) < 0)
    {
	perror ("listen");
	exit (1);
    }

    log ("listening on port %d", Server_Port);

#ifndef HAVE_DEV_RANDOM
    init_random ();
#endif /* !HAVE_DEV_RANDOM */

    /* main event loop */
    while (!SigCaught)
    {
	FD_ZERO (&set);
	maxfd = s;
	FD_SET (s, &set);

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
		n++;

		FD_SET (Clients[i]->fd, &set);
		if (Clients[i]->fd > maxfd)
		    maxfd = Clients[i]->fd;
	    }
	}

	Num_Clients = n; /* actual number of clients */

	t.tv_sec = Stat_Click;
	t.tv_usec = 0;

	n = select (maxfd + 1, &set, NULL, NULL, &t);

	if (n < 0)
	{
	    perror ("select");
	    break;
	}

	/* check for new incoming connections */
	if (FD_ISSET (s, &set))
	{
	    sinsize = sizeof (sin);
	    f = accept (s, (struct sockaddr *) &sin, &sinsize);
	    if (f < 0)
	    {
		perror ("accept");
	    }
	    else
	    {
		CONNECTION *cli;


		cli = new_connection ();
		cli->fd = f;
		cli->ip = sin.sin_addr.s_addr;
		cli->host = STRDUP (inet_ntoa (sin.sin_addr));
		cli->class = CLASS_UNKNOWN;
		log ("main(): connection from %s, port %d", cli->host,
			sin.sin_port);
		add_client (cli);

		if (fcntl (f, F_SETFL, O_NONBLOCK) != 0)
		    log ("main(): fcntl error (%s)", strerror (errno));

		/* make sure this ip is not banned */
		for (i = 0; i < Ban_Size; i++)
		{
		    if (Ban[i]->type == BAN_IP &&
			    ip_glob_match (Ban[i]->target, inet_ntoa (sin.sin_addr)))
		    {
			/* TODO: this does not reach all mods, only the one on
			   this server */
			notify_mods ("Connection attempt from banned ip %s",
				inet_ntoa (sin.sin_addr));
			send_cmd (cli, MSG_SERVER_ERROR, "You are banned from this server (%s)",
				Ban[i]->reason ? Ban[i]->reason : "banned");
			send_queued_data (cli);
			remove_connection (cli);
			break;
		    }
		}
	    }
	    n--;
	}

	/* handle client requests */
	for (i = 0; !SigCaught && n > 0 && i < Num_Clients; i++)
	{
	    /* client connections may disappear during this loop, so make
	       sure to check for a valid pointer before checking for input
	       from it.  the holes are reclaimed in a loop above (see
               comment there for more information) */
	    if (Clients[i] && FD_ISSET (Clients[i]->fd, &set))
	    {
		n--;	/* keep track of how many requests we've handled */
		handle_connection (Clients[i]);
	    }
	}

	/* we should send the clients updated server stats every so often */
	if (next_update < time (0))
	{
	    update_stats ();
	    next_update = time (0) + Stat_Click;
	}

	/* write out data for our clients now */
	for (i = 0; i < Num_Clients; i++)
	{
	    if (Clients[i] && Clients[i]->sendbuflen)
	    {
		/* we have data to send */
		send_queued_data (Clients[i]);
	    }
	}
    }

    if (SigCaught)
	log ("caught signal");

    log ("shutting down");

    /* close all client connections */
    for (i = 0; i < Num_Clients; i++)
    {
	if (Clients[i])
	    remove_connection (Clients[i]);
    }

    /* disallow incoming connections */
    close (s);

    close_db ();

    /* clean up */
    if (Clients)
	FREE (Clients);

    if (Servers)
	FREE (Servers);

    free_hash (Users);
    free_hash (Channels);
    free_hash (Hotlist);

    for(i=0;i<Ban_Size;i++)
	free_ban (Ban[i]);
    if (Ban)
	FREE (Ban);

    /* free up memory associated with global configuration variables */
    free_config ();

    /* this displays a list of leaked memory.  pay attention to this. */
    CLEANUP ();

    exit (0);
}
