/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$ */

#include <errno.h>
#include <string.h>
#include <fcntl.h>
#ifndef WIN32
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/time.h>
#include <sys/resource.h>
#endif /* !WIN32 */
#include "opennap.h"
#include "debug.h"

unsigned int
lookup_ip (const char *host)
{
    struct hostent *he;
    unsigned int ip;

    log ("lookup_ip(): resolving %s", host);
    /* check for dot-quad notation.  Win95's gethostbyname() doesn't seem
       to return the ip address properly for this case like every other OS */
    ip=inet_addr(host);
    if(ip==INADDR_NONE)
    {
	he = gethostbyname (host);
	if (!he)
	{
	    log ("lookup_ip(): can't find ip for host %s", host);
	    return 0;
	}
	memcpy (&ip, &he->h_addr[0], he->h_length);
    }
    log ("lookup_ip(): %s is %s", host, my_ntoa (ip));
    return ip;
}

int
set_nonblocking (int f)
{
    /* set the socket to be nonblocking */
#ifndef WIN32
    if (fcntl (f, F_SETFL, O_NONBLOCK) != 0)
#else
    int val = 1;

    if (ioctlsocket (f, FIONBIO, &val) != 0)
#endif /* !WIN32 */
    {
	log ("set_nonblocking(): fcntl: %s", strerror (errno));
	CLOSE (f);
	return -1;
    }
    return 0;
}

int
set_tcp_buffer_len (int f, int bytes)
{
    if (setsockopt (f, SOL_SOCKET, SO_SNDBUF, SOCKOPTCAST &bytes, sizeof (bytes)) == -1)
    {
	log ("set_tcp_buffer_len(): setsockopt: %s (errno %d)",
		strerror (errno), errno);
	return -1;
    }
    if (setsockopt (f, SOL_SOCKET, SO_RCVBUF, SOCKOPTCAST &bytes, sizeof (bytes)) == -1)
    {
	log ("set_tcp_buffer_len(): setsockopt: %s (errno %d)",
		strerror (errno), errno);
	return -1;
    }
    return 0;
}

int
new_tcp_socket (int options)
{
    int f;

    f = socket (AF_INET, SOCK_STREAM, 0);
    if (f < 0)
    {
	log("new_tcp_socket(): socket: %s", strerror (errno));
	return -1;
    }
    if(options & ON_NONBLOCKING)
    {
	if(set_nonblocking(f))
	    return -1;
    }
    if(options & ON_REUSEADDR)
    {
	int i = 1;
	if (setsockopt (f, SOL_SOCKET, SO_REUSEADDR, SOCKOPTCAST & i, sizeof (i))
		!= 0)
	{
	    nlogerr ("new_tcp_socket", "setsockopt");
	    exit (1);
	}
    }
    return f;
}

int
set_keepalive (int f, int on)
{
    if (setsockopt (f, SOL_SOCKET, SO_KEEPALIVE, SOCKOPTCAST &on, sizeof (on)) == -1)
    {
	log ("set_keepalive(): setsockopt: %s (errno %d).",
		strerror (errno), errno);
	return -1;
    }
    return 0;
}

int
bind_interface (int fd, unsigned int ip, int port)
{
    struct sockaddr_in sin;

    memset (&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = ip;
    sin.sin_port = htons (port);
    if (bind (fd, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
	log ("bind_interface(): bind: %s (errno %d)", strerror (errno), errno);
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
    if ((f = new_tcp_socket (ON_NONBLOCKING)) == -1)
	return -1;

    /* if an interface was specify, bind to it before connecting */
    if (Interface)
	bind_interface (f, Interface, 0);

    /* turn on TCP/IP keepalive messages */
    set_keepalive (f, 1);
    log ("make_tcp_connection(): connecting to %s:%hu",
	    inet_ntoa (sin.sin_addr), ntohs (sin.sin_port));
    if (connect (f, (struct sockaddr*) &sin, sizeof (sin)) < 0)
    {
	if (N_ERRNO != EINPROGRESS
#ifdef WIN32
	    /* winsock returns EWOULDBLOCK even in nonblocking mode! ugh!!! */
	    && N_ERRNO != EWOULDBLOCK
#endif
	    )
	{
	    nlogerr("make_tcp_connection","connect");
	    CLOSE (f);
	    return -1;
	}
	log ("make_tcp_connection(): connection to %s in progress", host);
    }
    else
	log ("make_tcp_connection(): connection established to %s", host);
    return f;
}

int
check_connect_status (int f)
{
    socklen_t len;
    int err;

    len = sizeof (err);

    if (getsockopt (f, SOL_SOCKET, SO_ERROR, SOCKOPTCAST &err, &len) != 0)
    {
	nlogerr ("check_connect_status","getsockopt");
	return -1;
    }
    if (err != 0)
    {
	_logerr ("check_connect_status","connect", err);
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

#if !defined(WIN32) && !defined(__EMX__)

#ifdef RLIMIT_FDMAX
# define RLIMIT_FD_MAX   RLIMIT_FDMAX
#else
# ifdef RLIMIT_NOFILE
#  define RLIMIT_FD_MAX RLIMIT_NOFILE
# else
#  ifdef RLIMIT_OPEN_MAX
#   define RLIMIT_FD_MAX RLIMIT_OPEN_MAX
#  else
#   undef RLIMIT_FD_MAX
#  endif
# endif
#endif

static int
set_limit (int attr, int value)
{
    struct rlimit lim;

    if (getrlimit (attr, &lim))
    {
	logerr ("set_limit_size", "getrlimit");
	return -1;
    }
    if (lim.rlim_max > 0 && value > lim.rlim_max)
    {
	/* give feedback to the operator if the default value is lower than
	   requested.  this is important when making the decision as to wheter
	   or not the server needs to be run as uid 0 */
	log ("set_limit(): warning: %d exceeds default hard limit of %d",
		value, lim.rlim_max);
    }
    lim.rlim_cur = value;
    if (lim.rlim_max > 0 && lim.rlim_cur > lim.rlim_max)
	lim.rlim_max = lim.rlim_cur;	/* adjust max value */
#ifndef HAVE_POLL
    if (attr == RLIMIT_FD_MAX && lim.rlim_cur > FD_SETSIZE)
    {
	log ("set_limit(): warning: compiled limit (%d) is smaller than hard limit (%d)",
		FD_SETSIZE, lim.rlim_max);
    }
#endif /* HAVE_POLL */
    if (setrlimit (attr, &lim))
    {
	logerr ("set_limit", "setrlimit");
	return -1;
    }
    return 0;
}

int
set_max_connections (int n)
{
    if (set_limit (RLIMIT_FD_MAX, n))
    {
	log ("set_max_connections(): unable to set resource limit");
	return -1;
    }
    log ("set_max_connections(): max connections set to %d", n);
    return 0;
}

int
set_data_size (int n)
{
    if (set_limit (RLIMIT_DATA, n))
    {
	log ("set_data_size(): unable to set resource limit");
	return -1;
    }
    log ("set_data_size(): max data segment size set to %d", n);
    return 0;
}

/* SysVR4 uses RLIMIT_AS (eg. Solaris) */
#ifndef RLIMIT_RSS
#define RLIMIT_RSS RLIMIT_AS
#endif

int
set_rss_size (int n)
{
    if (set_limit (RLIMIT_RSS, n))
    {
	log ("set_rss_size(): unable to set resource limit");
	return -1;
    }
    log ("set_rss_size(): max rss segment size set to %d", n);
    return 0;
}
#endif /* !WIN32 */

/* return the local port a socket is bound to */
unsigned short
get_local_port (int fd)
{
    struct sockaddr_in sin;
    socklen_t sinsize = sizeof (sin);
    if (getsockname (fd, (struct sockaddr *) &sin, &sinsize))
    {
	nlogerr ("get_local_port", "getsockname");
	return 0;
    }
    return (ntohs (sin.sin_port));
}
