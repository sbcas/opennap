/* Copyright (C) 2000 drscholl@sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include "opennap.h"
#include "debug.h"

/* interval at which we send server stats to our clients (in seconds) */
#define UPDATE_CLICK 60
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
int Num_Gigs = 0;
int Server_Port = 8888;		/* default */
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

void
send_stats (CONNECTION * con)
{
    send_cmd (con, MSG_SERVER_STATS, "%d %d %d", Users->dbsize, Num_Files,
	      Num_Gigs);
}

static void
usage (void)
{
    fprintf (stderr,
	     "usage: %s [ -c <config-file> ] [ -hv ] [ -p <port> ] \n",
	     PACKAGE);
    exit (0);
}

static void
version (void)
{
    fprintf (stderr, "%s %s\n", PACKAGE, VERSION);
    fprintf (stderr, "Copyright (C) 2000 drscholl@sourceforge.net\n");
    exit (0);
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
    { MSG_CLIENT_RESUME_REQUEST, resume }, /* 215 */
    { MSG_CLIENT_REMOVE_HOTLIST, remove_hotlist }, /* 303 */
    { MSG_CLIENT_WHOIS, whois },
    { MSG_CLIENT_JOIN, join },
    { MSG_CLIENT_PART, part },
    { MSG_CLIENT_PUBLIC, public },
    { MSG_SERVER_PUBLIC, public },
    { MSG_CLIENT_ANNOUNCE, announce },
    { MSG_CLIENT_KILL, kill_user },
    { MSG_CLIENT_DOWNLOAD, download },
    { MSG_CLIENT_DOWNLOAD_ACK, download_ack },
    { MSG_CLIENT_UPLOAD_COMPLETE, upload_complete },
    { MSG_SERVER_TOPIC, topic },
    { MSG_CLIENT_MUZZLE, muzzle },
    { MSG_CLIENT_UNMUZZLE, unmuzzle },
    { MSG_CLIENT_LIST_CHANNELS, list_channels }, /* 618 */
    { MSG_CLIENT_SETUSERLEVEL, level },
    { MSG_CLIENT_PING, ping }, /* 751 */
    { MSG_CLIENT_PONG, pong }, /* 752 */
    { MSG_CLIENT_NAMES_LIST, list_users }, /* 830 */

    /* non-standard messages */
    {MSG_CLIENT_QUIT, client_quit},
    {MSG_SERVER_LOGIN, server_login},
    {MSG_CLIENT_CONNECT, server_connect},
    {MSG_SERVER_LOGIN, server_login},
    {MSG_SERVER_LOGIN_ACK, server_login_ack}
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

#if __BYTE_ORDER == __BIG_ENDIAN
    /* need to convert to big endian */
    len = bswap_16 (len);
    tag = bswap_16 (tag);
#endif

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

void
defaults (void)
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

    Motd_Path = STRDUP (SHAREDIR "/motd");
    Db_Host = STRDUP ("localhost");
    Db_User = STRDUP ("mp3");
    Db_Name = STRDUP ("mp3");
    Db_Pass = STRDUP ("passtest");
}

void
update_stats (void)
{
    int i, l;

    /* since we send the same data to many people, optimize by forming
       the message once then writing it out */
    snprintf (Buf + 4, sizeof (Buf) - 4, "%d %d %d", Users->dbsize, Num_Files,
	Num_Gigs);
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
    size_t sinsize;
    time_t next_update = 0;
    struct timeval t = { UPDATE_CLICK, 0 };

    log ("version %s starting", VERSION);

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
	case 'v':
	    version ();
	    break;
	case 'h':
	default:
	    usage ();
	}
    }

    /* load default configuration values */
    defaults();

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

#ifdef linux
	/* under linx, select() modifies this to return the amount of time
	   not slept, so we have to reset the value.  for some strange
           reason, signals get blocked if you don't reset this value
	   anyone know why? */
	t.tv_sec = UPDATE_CLICK;
	t.tv_usec = 0;
#endif /* linux */

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

		cli = CALLOC (1, sizeof (CONNECTION));
		cli->fd = f;
		cli->ip = sin.sin_addr.s_addr;
		cli->host = STRDUP (inet_ntoa (sin.sin_addr));
		cli->class = CLASS_UNKNOWN;
		log ("main(): connection from %s, port %d", cli->host,
		     sin.sin_port);
		add_client (cli);

		if (fcntl (f, F_SETFL, O_NONBLOCK) != 0)
		    log ("main(): fcntl error (%s)", strerror (errno));
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
	    next_update = time (0) + UPDATE_CLICK;
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

    FREE (Db_Host);
    FREE (Db_User);
    FREE (Db_Pass);
    FREE (Db_Name);
    FREE (Motd_Path);
    FREE (Server_Name);
    if (Server_Pass)
    FREE (Server_Pass);

    /* this displays a list of leaked memory.  pay attention to this. */
    CLEANUP ();

    exit (0);
}
