/* Copyright (C) 2000 drscholl@sourceforge.net
   This is free software distributed under the terms of the GNU Public
   License.  See the file COPYING for details. */

#include <stdio.h>
#include <readline/readline.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

/* very simple client to test server responses */

int Fd;
char Buf[512];
int Quit = 0;

void user_input (char *s)
{
    short len, type;
    char *p;

    if (*s == '/')
    {
	s++;
	if (!strncmp ("join", s, 4))
	{
	    s+=4;
	    type = 400;
	}
	else if (!strncmp ("part", s, 4))
	{
	    s+=4;
	    type = 401;
	}
	else if (!strncmp ("quit", s, 4))
	{
	    Quit = 1;
	    return;
	}
	else if (!strncmp("search", s, 6))
	{
	    s+=6;
	    type=200;
	    snprintf (Buf, sizeof (Buf), "FILENAME CONTAINS \"%s\" MAX_RESULTS 100", s);
	    s = Buf;
	}
	else if (!strncmp("browse", s, 5))
	{
	    s+=5;
	    type=211;
	}
	else if (!strncmp("get", s, 3))
	{
	    s += 3;
	    type = 203;
	}
	else
	{
	    puts("\runknown command[K");
	    return;
	}
	while (isspace (*s))
	    s++;
	p = s;
    }
    else
    {
	p = strchr (s, ' ');
	if (p)
	    *p++ = 0;
	type = atoi (s);
    }
    len = strlen (p);

    write (Fd, &len, 2);
    write (Fd, &type, 2);
    if (len)
	write (Fd, p, len);
}

int
server_output (void)
{
    short len, msg, bytes = 0, l;

    l = read (Fd, &len, 2);
    if (l != 2)
    {
	printf ("\rcould not read packet length (%hd)\n", l);
	return -1;
    }
    l = read (Fd, &msg, 2);
    if (l != 2)
    {
	printf ("\rcould not read packet type (%hd)\n", l);
	return -1;
    }
    while (bytes < len)
    {
	l = read (Fd, Buf + bytes, len - bytes);
	if (l == -1)
	{
	    perror ("read");
	    return -1;
	}
	if (l == 0)
	{
	    puts ("EOF from server");
	    return -1;
	}
	bytes += l;
    }
    Buf[bytes] = 0;

    printf ("\rlen=%hd, type=%hd, data=%s\n", len, msg, Buf);
    rl_forced_update_display ();
    return 0;
}

int
main (int argc, char **argv)
{
    int i;
    char *server = 0;
    int port = 8888;
    struct sockaddr_in sin;
    fd_set rFds;
    char *user = "kuila0";
    struct hostent *he;
    int reconnect = 0;

    while ((i = getopt (argc, argv, "rs:p:u:")) != -1)
    {
	switch (i)
	{
	    case 'r':
		reconnect = 1;
		break;
	    case 's':
		server = optarg;
		break;
	    case 'p':
		port = atoi (optarg);
		break;
	    case 'u':
		user = optarg;
		break;
	}
    }

    memset (&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET;

    Fd = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (Fd < 0)
    {
	perror ("socket");
	exit (1);
    }

    /* if no server was specified, ask the metaserver */
    if (!server)
    {
	FILE *fp;
	char *cp;

	printf ("getting best host...");
	fflush (stdout);
	sin.sin_port = htons (8875);
	he = gethostbyname ("server.napster.com");
	if (!he)
	{
	    perror ("gethostbyname");
	    exit (1);
	}
	sin.sin_addr.s_addr = *((long *) he->h_addr_list[0]);
	endhostent ();

	if (connect (Fd, (struct sockaddr *) &sin, sizeof (sin)) < 0)
	{
	    perror ("connect");
	    exit (1);
	}
	fp = fdopen (Fd, "r+");
	if (!fp)
	{
	    perror ("Fdopen");
	    exit (1);
	}
	fgets (Buf, sizeof (Buf), fp);
	fclose (fp);
	fputs (Buf, stdout);

	cp = strchr (Buf, '\n');
	if (cp)
	    *cp = 0;

	cp = strchr (Buf, ':');
	if (!cp)
	{
	    printf ("unable to parse metaserver response: %s", Buf);
	    exit (1);
	}
	*cp++ = 0;
	sin.sin_port = htons (atoi (cp));
	if (inet_aton (Buf, &sin.sin_addr) == 0)
	{
	    printf ("unable to convert %s to an ip address\n", Buf);
	    exit (1);
	}

	Fd = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (Fd < 0)
	{
	    perror ("socket");
	    exit (1);
	}
    }
    else
    {
	he = gethostbyname (server);
	if (!he)
	{
	    perror ("gethostbyname");
	    exit (1);
	}
	sin.sin_port = htons (port);
	sin.sin_addr.s_addr = *((long *) he->h_addr_list[0]);
	endhostent ();
    }

reconnect:

    printf ("connecting to %s port %hu...", inet_ntoa (sin.sin_addr), ntohs (sin.sin_port));
    fflush (stdout);

    if (connect (Fd, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
	perror ("connect");

	if (reconnect)
	    goto reconnect;

	exit (1);
    }

    puts ("connected.");

    /* send the login command */
    snprintf (Buf + 4, sizeof (Buf) - 4, "%s password 0 \"nap v0.9\" 3", user);
    Buf[0] = strlen (Buf + 4);
    Buf[1] = 0;
    Buf[2] = 2;
    Buf[3] = 0;
    write (Fd, Buf, Buf[0] + 4);

    FD_ZERO (&rFds);

    rl_callback_handler_install ("spynap> ", user_input);

    while (!Quit)
    {
	FD_SET (0, &rFds);
	FD_SET (Fd, &rFds);
	if (select (Fd + 1, &rFds, 0, 0, 0) == -1)
	{
	    perror ("select");
	    break;
	}
	if (FD_ISSET (0, &rFds))
	    rl_callback_read_char ();
	if (FD_ISSET (Fd, &rFds))
	{
	    if (server_output () != 0)
		break;
	}
    }

    close (Fd);

    exit (0);
}
