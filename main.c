/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
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
int Server_Queue_Length;
int Client_Queue_Length;
int Max_Search_Results;
int Compression_Level;
int Compression_Threshold;
int Max_Shared;
int Max_Connections;

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

HANDLER (server_stats)
{
    (void) pkt;
    (void) tag;
    (void) len;
    send_cmd (con, MSG_SERVER_STATS, "%d %d %d", Users->dbsize, Num_Files,
	      Num_Gigs / (1024 * 1024));
}

typedef struct
{
    unsigned long message;
      HANDLER ((*handler));
}
HANDLER;

/* this is the table of valid commands we accept from both users and servers */
static HANDLER Protocol[] = {
    {MSG_CLIENT_LOGIN, login},	/* 6 */
    {MSG_CLIENT_LOGIN_REGISTER, login},	/* 7 */
    {MSG_CLIENT_ADD_FILE, add_file},	/* 100 */
    {MSG_CLIENT_REMOVE_FILE, remove_file},	/* 102 */
    {MSG_CLIENT_SEARCH, search},	/* 200 */
    {MSG_CLIENT_PRIVMSG, privmsg},	/* 205 */
    {MSG_CLIENT_ADD_HOTLIST, add_hotlist},	/* 207 */
    {MSG_CLIENT_ADD_HOTLIST_SEQ, add_hotlist},	/* 208 */
    {MSG_CLIENT_BROWSE, browse},	/* 211 */
    {MSG_SERVER_STATS, server_stats},	/* 214 */
    {MSG_CLIENT_RESUME_REQUEST, resume},	/* 215 */
    {MSG_CLIENT_DOWNLOAD_START, download_start},	/* 218 */
    {MSG_CLIENT_DOWNLOAD_END, download_end},	/* 219 */
    {MSG_CLIENT_UPLOAD_START, upload_start},	/* 220 */
    {MSG_CLIENT_UPLOAD_END, upload_end},	/* 221 */
    {MSG_CLIENT_REMOVE_HOTLIST, remove_hotlist},	/* 303 */
    {MSG_SERVER_NOSUCH, server_error},	/* 404 */
    {MSG_CLIENT_DOWNLOAD_FIREWALL, download},	/* 500 */
    {MSG_CLIENT_WHOIS, whois},
    {MSG_CLIENT_JOIN, join},
    {MSG_CLIENT_PART, part},
    {MSG_CLIENT_PUBLIC, public},
    {MSG_SERVER_PUBLIC, public},
    {MSG_CLIENT_USERSPEED, user_speed},	/* 600 */
    {MSG_CLIENT_KILL, kill_user},
    {MSG_CLIENT_DOWNLOAD, download},
    {MSG_CLIENT_UPLOAD_OK, upload_ok},
    {MSG_SERVER_UPLOAD_REQUEST, upload_request},	/* 607 */
    {MSG_SERVER_TOPIC, topic},
    {MSG_CLIENT_MUZZLE, muzzle},
    {MSG_CLIENT_UNMUZZLE, unmuzzle},
    {MSG_CLIENT_BAN, ban},	/* 612 */
    {MSG_CLIENT_UNBAN, unban},	/* 614 */
    {MSG_CLIENT_BANLIST, banlist},	/* 615 */
    {MSG_CLIENT_LIST_CHANNELS, list_channels},	/* 618 */
    {MSG_CLIENT_DATA_PORT_ERROR, data_port_error},	/* 626 */
    {MSG_CLIENT_WALLOP, wallop},	/* 627 */
    {MSG_CLIENT_ANNOUNCE, announce},	/* 628 */
    {MSG_CLIENT_SETUSERLEVEL, level},
    {MSG_CLIENT_PING, ping},	/* 751 */
    {MSG_CLIENT_PONG, ping},	/* 752 */
    {MSG_CLIENT_SERVER_RECONFIG, server_reconfig},	/* 800 */
    {MSG_CLIENT_SERVER_VERSION, server_version},	/* 801 */
    {MSG_CLIENT_SERVER_CONFIG, server_config},	/* 810 */
    {MSG_CLIENT_NAMES_LIST, list_users},	/* 830 */

    /* non-standard messages */
    {MSG_CLIENT_QUIT, client_quit},
    {MSG_SERVER_LOGIN, server_login},
    {MSG_SERVER_LOGIN, server_login},
    {MSG_SERVER_LOGIN_ACK, server_login_ack},
    {MSG_SERVER_USER_IP, user_ip},	/* 10013 */
    {MSG_CLIENT_CONNECT, server_connect},	/* 10100 */
    {MSG_CLIENT_DISCONNECT, server_disconnect},	/* 10101 */
    {MSG_CLIENT_KILL_SERVER, kill_server},	/* 10110 */
    {MSG_CLIENT_REMOVE_SERVER, remove_server},	/* 10111 */
#if 0
    {MSG_SERVER_COMPRESSED_DATA, compressed_data},	/* 10200 */
#endif
};
static int Protocol_Size = sizeof (Protocol) / sizeof (HANDLER);

/* this is not a real handler, but takes the same arguments as one */
HANDLER (dispatch_command)
{
    int l;
    unsigned char byte;

    ASSERT (validate_connection (con));

    /* HACK ALERT
       the handler routines all assume that the `pkt' argument is nul (\0)
       terminated, so we have to replace the byte after the last byte in
       this packet with a \0 to make sure we dont read overflow in the
       handlers.  the buffer_read() function should always allocate 1 byte
       more than necessary for this purpose */
    byte = *(pkt + len);
    ASSERT (byte != END_BYTE);	/* make sure we didn't run off the end of the
				   buffer */
    *(pkt + len) = 0;

    for (l = 0; l < Protocol_Size; l++)
    {
	if (Protocol[l].message == tag)
	{
	    ASSERT (Protocol[l].handler != 0);
	    /* note that we pass only the data part of the packet */
	    Protocol[l].handler (con, tag, len, pkt);
	    break;
	}
    }

    if (l == Protocol_Size)
    {
	log
	    ("dispatch_command(): unknown message: tag=%hu, length=%hu, data=%s",
	     tag, len,
	     len ? (char *) con->recvbuf->data +
	     con->recvbuf->consumed : "(empty)");

	send_cmd (con, MSG_SERVER_NOSUCH, "unknown command code %hu", tag);
    }

    /* restore the byte we overwrite at the beginning of this function */
    *(pkt + len) = byte;
}

static void
handle_connection (CONNECTION * con)
{
    unsigned short len, tag;

    ASSERT (validate_connection (con));

#if HAVE_LIBZ
    /* decompress server input stream */
    if (con->class == CLASS_SERVER)
    {
	BUFFER *b;

	ASSERT (con->zip != 0);
	if (con->zip->inbuf
	    && (b = buffer_uncompress (con->zip->zin, &con->zip->inbuf)))
	    con->recvbuf = buffer_append (con->recvbuf, b);
    }
#endif /* HAVE_LIBZ */

    /* check if there is enough data in the buffer to read the packet header */
    if (buffer_size (con->recvbuf) < 4)
    {
	/* we set this flag here to avoid busy waiting in the main select()
	   loop.  we can't process any more input until we get some more
	   data */
	con->incomplete = 1;
	return;
    }
    /* make sure all 4 bytes of the header are in the first block */
    buffer_group (con->recvbuf, 4);
    memcpy (&len, con->recvbuf->data + con->recvbuf->consumed, 2);
    memcpy (&tag, con->recvbuf->data + con->recvbuf->consumed + 2, 2);

    /* need to convert to little endian */
    len = BSWAP16 (len);
    tag = BSWAP16 (tag);

    /* see if all of the packet body is present */
    if (buffer_size (con->recvbuf) < 4 + len)
    {
	/* nope, wait until more data arrives */
	con->incomplete = 1;
	return;
    }

    con->incomplete = 0;	/* found all the data we wanted */

    /* the packet may be fragmented so make sure all of the bytes for this
       packet end up in the first buffer so its easy to handle */
    buffer_group (con->recvbuf, 4 + len);

#ifndef HAVE_DEV_RANDOM
    add_random_bytes (recvbuf->data + recvbuf->consumed, 4 + len);
#endif /* !HAVE_DEV_RANDOM */

    /* require that the client register before doing anything else */
    if (con->class == CLASS_UNKNOWN &&
	(tag != MSG_CLIENT_LOGIN && tag != MSG_CLIENT_LOGIN_REGISTER &&
	 tag != MSG_CLIENT_REGISTER && tag != MSG_SERVER_LOGIN &&
	 tag != MSG_SERVER_LOGIN_ACK && tag != MSG_SERVER_ERROR))
    {
	log ("handle_connection: %s is not registered, closing connection",
	     con->host);
	log ("handle_connection: tag=%hu, len=%hu, data=%d",
		tag, len, con->recvbuf->data + con->recvbuf->consumed + 4);
	remove_connection (con);
	return;
    }

    /* if we received this message from a peer server, pass it
       along to the other servers behind us.  the ONLY messages we don't
       propogate are an ACK from a peer server that we've requested a link
       with, and an error message from a peer server */
    if (con->class == CLASS_SERVER && tag != MSG_SERVER_LOGIN_ACK &&
	tag != MSG_SERVER_NOSUCH && Num_Servers)
	pass_message (con, con->recvbuf->data + con->recvbuf->consumed,
		      4 + len);

    dispatch_command (con, tag, len,
		      con->recvbuf->data + con->recvbuf->consumed + 4);

    if (con->destroy)
    {
	log ("handle_connection: closing connection to %s", con->host);
	remove_connection (con);
    }
    else
	/* mark that we read this data and it is ok to free it */
	con->recvbuf = buffer_consume (con->recvbuf, len + 4);
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
    endhostent ();
}

static void
update_stats (void)
{
    int i, l;

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
usage (void)
{
    fprintf (stderr,
	     "usage: %s [ -hsv ] [ -c FILE ] [ -p PORT ] \n", PACKAGE);
    fprintf (stderr, "  -c FILE	read config from FILE (default: %s/config\n",
	     SHAREDIR);
    fputs ("  -h		print this help message\n", stderr);
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
    struct sockaddr_in sin;
    int s;			/* server socket */
    int i;			/* generic counter */
    int n;			/* number of ready sockets */
    int f;			/* new socket for incoming connection */
    int pending = 0;
    int port = 0, maxfd;
    fd_set set, wset;
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
    s = new_tcp_socket ();
    if (s < 0)
	exit (1);

    n = 1;
    if (setsockopt (s, SOL_SOCKET, SO_REUSEADDR, &n, sizeof (n)) != 0)
    {
	perror ("setsockopt");
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

#ifndef HAVE_DEV_RANDOM
    init_random ();
#endif /* !HAVE_DEV_RANDOM */

    /* main event loop */
    while (!SigCaught)
    {
	FD_ZERO (&set);
	FD_ZERO (&wset);
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

		/* check sockets for writing */
		if ((Clients[i]->flags & FLAG_CONNECTING) ||
		    (Clients[i]->sendbuf ||
		     (Clients[i]->zip && Clients[i]->zip->outbuf)))
		    FD_SET (Clients[i]->fd, &wset);

		/* always check for incoming data */
		FD_SET (Clients[i]->fd, &set);

		if (Clients[i]->fd > maxfd)
		    maxfd = Clients[i]->fd;

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
	t.tv_sec = pending ? 0 : Stat_Click;
	t.tv_usec = 0;

	pending = 0;		/* reset */

	n = select (maxfd + 1, &set, &wset, NULL, &t);

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

		set_nonblocking (f);
		set_keepalive (f, 1);	/* enable tcp keepalive messages */

		if (!check_accept (cli))
		    remove_connection (cli);
	    }
	    n--;
	}

	/* read incoming data into buffers, but don't process it */
	for (i = 0; !SigCaught && n > 0 && i < Num_Clients; i++)
	{
	    /* client connections may disappear during this loop, so make
	       sure to check for a valid pointer before checking for input
	       from it.  the holes are reclaimed in a loop above (see
	       comment there for more information) */
	    if (Clients[i])
	    {
		if ((Clients[i]->flags & FLAG_CONNECTING) &&
		    FD_ISSET (Clients[i]->fd, &wset))
		{
		    complete_connect (Clients[i]);
		    n--;	/* keep track of how many we've handled */
		}
		else if (FD_ISSET (Clients[i]->fd, &set))
		{
		    n--;	/* keep track of how many we've handled */
		    f = buffer_read (Clients[i]->fd,
				     (Clients[i]->zip !=
				      0) ? &Clients[i]->zip->
				     inbuf : &Clients[i]->recvbuf);
		    if (f <= 0)
		    {
			if (f == 0)
			    log ("main: EOF from %s", Clients[i]->host);
			remove_connection (Clients[i]);
		    }
		}
	    }
	}

	if (SigCaught)
	    break;

	/* handle client requests */
	for (i = 0; !SigCaught && i < Num_Clients; i++)
	{
	    if (Clients[i])
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

	/* write out data for our clients now */
	for (i = 0; !SigCaught && i < Num_Clients; i++)
	{
	    /* test for existence since it may have disappeared in the
	       handle_connection() call */
	    if (Clients[i])
	    {
		if (Clients[i]->zip)
		{
		    /* server - strategy is call send_queued_data() if there
		       there is no compressed data and some queued data
		       exists, or if the socket is writable and there is some
		       compressed output */
		    if ((Clients[i]->sendbuf && Clients[i]->zip->outbuf == 0)
			|| (Clients[i]->zip->outbuf
			    && FD_ISSET (Clients[i]->fd, &wset)))
			send_queued_data (Clients[i]);
		}
		else
		{
		    /* client */
		    if (Clients[i]->sendbuf
			&& FD_ISSET (Clients[i]->fd, &wset))
			send_queued_data (Clients[i]);
		}
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

    for (i = 0; i < Ban_Size; i++)
	free_ban (Ban[i]);
    if (Ban)
	FREE (Ban);

    /* free up memory associated with global configuration variables */
    free_config ();

    /* this displays a list of leaked memory.  pay attention to this. */
    CLEANUP ();

    exit (0);
}
