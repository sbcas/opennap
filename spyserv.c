/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

/* a simple proxy server to spy on the traffic between client and server.  this
   is a lot easier than using tcpdump.  use the fake metaserver to redirect
   clients to this server */

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

unsigned char buf[2048];

#define NAP_SERVER "208.49.239.247"
#define NAP_PORT 6666

int
read_bytes (int fd, int n, unsigned char *b)
{
    int t = 0, l;

    while (t < n)
    {
	l = read (fd, b + t, n - t);
	if (l <= 0)
	{
	    if(l == -1)
		perror("read");
	    puts("read_bytes(): error reading data");
	    return -1;
	}
	t += l;
    }
    return t;
}

int
pass_message (const char *id, int s, int d)
{
    int len;

    if (read_bytes (s, 4, buf) == -1)
	return -1;

    len = buf[0] | (buf[1] << 8);
    if (read_bytes (s, len, buf + 4) == -1)
	return -1;
    buf[4 + len] = 0;
    printf ("%s: tag=%d, len=%d, data=%s\n",
	    id, buf[2] | (buf[3] << 8), len, (char *) buf + 4);

    write (d, buf, 4 + len);
    return 0;
}

static void
usage(void)
{
    puts("usage: spyserv [ -h SERVER ] [ -p SERVERPORT ] [ -l LOCALPORT ]");
    exit(0);
}

int
main (int argc, char **argv)
{
    int s;
    int c;
    int r;
    int localport = 8888;
    size_t sinsize;
    struct sockaddr_in sin;
    fd_set fds;
    char *host = NAP_SERVER;
    int port = NAP_PORT;

    while ((r = getopt (argc, argv, "hs:p:l:")) != EOF)
    {
	switch (r)
	{
	    case 'l':
		localport = atoi(optarg);
		break;
	case 's':
	    host = optarg;
	    break;
	case 'p':
	    port = atoi (optarg);
	    break;
	default:
	    usage();
	}
    }

    /* accept connection from client */
    s = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0)
    {
	perror ("socket");
	exit (1);
    }
    c=1;
    if(setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&c,sizeof(c))!=0)
    {
	perror("setsockopt");
	exit(1);
    }
    memset (&sin, 0, sizeof (sin));
    sin.sin_port = htons (localport);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    if (bind (s, &sin, sizeof (sin)) < 0)
    {
	perror ("bind");
	exit (1);
    }
    if (listen (s, 1) < 0)
    {
	perror ("listen");
	exit (1);
    }
    puts ("waiting for client");
    if (select (s + 1, &fds, 0, 0, 0) < 0)
    {
	perror ("select");
	exit (1);
    }
    sinsize = sizeof (sin);
    c = accept (s, &sin, &sinsize);
    if (c < 0)
    {
	perror ("accept");
	exit (1);
    }
    puts ("got client");

    /* make connection to server */
    printf ("connecting to server...");
    fflush(stdout);
    r = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (r < 0)
    {
	perror ("socket");
	exit (1);
    }
    memset (&sin, 0, sizeof (sin));
    sin.sin_port = htons (port);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr (host);
    if (connect (r, &sin, sizeof (sin)) < 0)
    {
	perror ("connect");
	exit (1);
    }
    puts ("connected to server");

    for (;;)
    {
	FD_ZERO (&fds);
	FD_SET (r, &fds);
	FD_SET (c, &fds);
	if (select (((r > c) ? r : c) + 1, &fds, 0, 0, 0) < 0)
	{
	    perror ("select");
	    break;
	}
	if (FD_ISSET (r, &fds))
	{
	    if (pass_message ("server", r, c) != 0)
		break;
	}
	if (FD_ISSET (c, &fds))
	{
	    if (pass_message ("client", c, r) != 0)
		break;
	}
    }
    close (r);
    close (s);
    close (c);
    exit (0);
}
