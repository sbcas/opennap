/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License. */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include "opennap.h"
#include "debug.h"

void
try_connect (char *host, int port)
{
    struct hostent *he;
    struct sockaddr_in sin;
    unsigned long ip;
    int f;
    CONNECTION *cli;

    log ("try_connect(): attempting to establish server connection to %s:%d",
	    host, port);

    /* attempt a connection */
    memset (&sin, 0, sizeof (sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons (port);
    he=gethostbyname(host);
    if (!he)
    {
	log ("try_connect(): can't find ip for host %s", host);
	return;
    }
    memcpy (&ip, &he->h_addr[0], he->h_length);
    endhostent();
    sin.sin_addr.s_addr = ip;

    f=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(f<0)
    {
	log("server_connect(): socket: %s", strerror (errno));
	return;
    }
    if (connect(f,(struct sockaddr*)&sin,sizeof(sin))<0)
    {
	log("server_connect(): connect: %s", strerror (errno));
	close (f);
	return;
    }

    /* set the socket to be nonblocking */
    if (fcntl (f, F_SETFL, O_NONBLOCK) != 0)
    {
	log("server_connect(): fcntl: %s", strerror (errno));
	close (f);
	return;
    }

    cli = CALLOC (1, sizeof (CONNECTION));
    cli->class = CLASS_UNKNOWN; /* not authenticated yet */
    cli->fd = f;
    cli->host = STRDUP (host);
    cli->nonce = generate_nonce ();
    cli->ip = ip;

    add_client (cli);

    /* send the login request */
    ASSERT (Server_Name != 0);
    send_cmd (cli, MSG_SERVER_LOGIN, "%s %s", Server_Name, cli->nonce);

    /* we handle the response to the login request in the main event loop so
       that we don't block while waiting for th reply.  if the server does
       not accept our connection it will just drop it and we will detect
       it by the normal means that every other connection is checked */
}

/* process client request to link another server */
/* <server-name> <port> */
HANDLER (server_connect)
{
    char *fields[2];

    ASSERT (VALID (con));

    CHECK_USER_CLASS ("server_connect");

    ASSERT (VALID (con->user));

    if ((con->user->flags & FLAG_ADMIN) != 0)
    {
	send_cmd (con, MSG_SERVER_NOSUCH, "permission denied");
	log ("server_connect(): user %s tried to connect to %s", pkt);
	return; /* no privilege */
    }

    if (split_line (fields, sizeof (fields) / sizeof (char *), pkt) != 2)
    {
	log ("server_connect(): wrong number of fields");
	return;
    }

    try_connect (fields[0], atoi (fields[1]));
}

/* this will eventually go away once there is proper support in clients to
   call the server_connect() function */
void
try_connect_privmsg (char *s)
{
    char *ptr;

    while (*s == ' ')
	s++;
    ptr = strchr (s, ' ');
    if (!ptr)
	return;
    *ptr++ = 0;
    try_connect (s, atoi (ptr));
}
