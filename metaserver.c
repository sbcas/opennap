/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details. */

/* a simple napster metaserver.  redirects clients to a specific set of
   servers */

#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>

static void
handler (int sig)
{
    (void) sig;
}

static void
usage (void)
{
    puts ("usage: metaserver [ -v ] [ -p <port> ] [ host:port ... ]");
    puts ("  -v		display version number and exit");
    puts ("  -p <port>	listen for connection on <port> (default is 8875)\n");
    puts ("  if no arguments are given, defaults to 127.0.0.1:8888");
    exit (1);
}

int
main (int argc, char **argv)
{
    char *hosts[32];
    int numhosts = 0;
    struct sockaddr_in sin;
    int s, f;
    fd_set set;
    socklen_t sinsize;
    struct sigaction sa;
    int i;
    int port = 8875;

    while ((i = getopt (argc, argv, "hvp:"))!=EOF)
    {
	switch (i)
	{
	    case 'p':
		port = atoi (optarg);
		break;
	    case 'v':
		printf("%s metaserver version %s\n", PACKAGE, VERSION);
		exit(1);
	    default:
		usage();
	}
    }

    /* read in the host list */
    if (!argv[optind])
	hosts[numhosts++] = strdup ("127.0.0.1:8888"); /* use default host */
    else
    {
	while (argv[optind])
	{
	    hosts[numhosts++] = strdup (argv[optind]);
	    optind++;
	}
    }

    /* set some signal handlers so we can shut down gracefully */
    memset (&sa, 0, sizeof (sa));
    sa.sa_handler = handler;
    sigaction (SIGINT, &sa, 0);
    sigaction (SIGHUP, &sa, 0);
    sigaction (SIGTERM, &sa, 0);

    memset (&sin, 0, sizeof (sin));
    sin.sin_port = htons (port);
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;

    s = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0)
    {
	perror ("socket");
	exit (1);
    }
    if (bind (s, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
	perror ("bind");
	exit (1);
    }
    if (listen (s, 5) < 0)
    {
	perror ("listen");
	exit (1);
    }
    i=0;
    for (;;)
    {
	FD_ZERO (&set);
	FD_SET (s, &set);
	if (select (s + 1, &set, 0, 0, 0) < 0)
	{
	    perror ("select");
	    break;
	}
	sinsize = sizeof (sin);
	f = accept (s, (struct sockaddr *) &sin, &sinsize);
	if (f < 0)
	{
	    perror ("accept");
	    break;
	}
	write (f, hosts[i], strlen(hosts[i]));
	i = (i+1) % numhosts;
	close (f);
    }
    close (s);
    exit (0);
}
