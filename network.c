/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "opennap.h"
#include "debug.h"

unsigned int
lookup_ip (const char *host)
{
    struct hostent *he;
    unsigned int ip;

    log ("lookup_ip: resolving %s", host);
    he = gethostbyname(host);
    if (!he)
    {
	log ("lookup_ip: can't find ip for host %s", host);
	return 0;
    }
    memcpy (&ip, &he->h_addr[0], he->h_length);
    endhostent ();
    log ("lookup_ip: %s is %s", host, my_ntoa (ip));
    return ip;
}

int
set_nonblocking (int f)
{
    /* set the socket to be nonblocking */
    if (fcntl (f, F_SETFL, O_NONBLOCK) != 0)
    {
	log("set_nonblocking(): fcntl: %s", strerror (errno));
	close (f);
	return -1;
    }
    return 0;
}

int
new_tcp_socket (void)
{
    int f;

    f = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (f < 0)
    {
	log("new_tcp_socket(): socket: %s", strerror (errno));
	return -1;
    }
    return f;
}

int
set_keepalive (int f, int on)
{
    if (setsockopt (f, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof (on)) == -1)
    {
	log ("set_keepalive(): setsockopt: %s (errno %d).",
		strerror (errno), errno);
	return -1;
    }
    return 0;
}

int
make_tcp_connection (const char *host, int port, unsigned int *ip)
{
    struct sockaddr_in sin;
    int f;

    memset (&sin, 0, sizeof (sin));
    sin.sin_port = htons (port);
    sin.sin_family = AF_INET;
    if ((sin.sin_addr.s_addr = lookup_ip (host)) == 0)
	return -1;
    if (ip)
	*ip = sin.sin_addr.s_addr;
    if ((f = new_tcp_socket ()) == -1)
	return -1;
    if (set_nonblocking (f) == -1)
	return -1;
    /* turn on TCP/IP keepalive messages */
    set_keepalive (f, 1);
    log ("make_tcp_connection: connecting to %s:%hu",
	    inet_ntoa (sin.sin_addr), ntohs (sin.sin_port));
    if (connect (f, (struct sockaddr*) &sin, sizeof (sin)) < 0)
    {
	if (errno != EINPROGRESS)
	{
	    log("make_tcp_connection: connect: %s", strerror (errno));
	    close (f);
	    return -1;
	}
	log ("make_tcp_connection: connection to %s in progress", host);
    }
    else
	log ("make_tcp_connection: connection established to %s", host);
    return f;
}

int
check_connect_status (int f)
{
    socklen_t len;
    int err;

    len = sizeof (err);

    if (getsockopt (f, SOL_SOCKET, SO_ERROR, &err, &len) != 0)
    {
	log ("check_connect_status: getsockopt: %s (errno %d).",
		strerror (errno), errno);
	return -1;
    }
    if (err != 0)
    {
	log ("check_connect_status: connect: %s (errno %d).",
		strerror (err), err);
	return -1;
    }
    return 0;
}

char *
my_ntoa (unsigned int ip)
{
    struct in_addr a;

    memset (&a, 0, sizeof (a));
    a.s_addr = ip;
    return (inet_ntoa (a));
}
