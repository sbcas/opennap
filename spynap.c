/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the GNU Public
   License.  See the file COPYING for details. */

#define PACKAGE "spynap"
#define VERSION "0.08"

#include <stdio.h>
#include <readline/readline.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>

/* very simple client to test server responses */

int Fd;
char Buf[512];
int Quit = 0;
char *Nick;
int Output = 0;

struct search {
    char *user;
    char *file;
    int speed;
    int bitrate;
};

struct search *Search = 0;
int Search_Size = 0;

struct xmit {
    int upload;
    int download;
    int fd;
    FILE *fp;
    int bytes;
    int filesize;
    time_t start;
    char *filename;
    char *nick;
};

struct xmit **Transfer = 0;
int Transfer_Size = 0;

static void
do_output (const char *fmt, ...)
{
    va_list ap;
    char buf[128];
    va_start(ap,fmt);
    vsnprintf(buf,sizeof(buf),fmt,ap);
    va_end(ap);
    if(!Output)
	fputc('\r', stdout);
    fputs("-:- ",stdout);
    fputs(buf,stdout);
    if(!Output)
    {
	Output=1;
	fputs("[K", stdout);
    }
    fputc('\n', stdout);
}

/* this is like strtok(2), except that all fields are returned as once.  nul
   bytes are written into `pkt' and `template' is updated with pointers to
   each field in `pkt' */
/* returns: number of fields found. */
static int
split_line (char **template, int templatecount, char *pkt)
{
    int i = 0;

    while (pkt && i < templatecount)
    {
	if (*pkt == '"')
	{
	    /* quoted string */
	    pkt++;
	    template[i++] = pkt;
	    pkt = strchr (pkt, '"');
	    if (!pkt)
	    {
		/* bogus line */
		return -1;
	    }
	    *pkt++ = 0;
	    if (!*pkt)
		break;
	    pkt++;		/* skip the space */
	}
	else
	{
	    template[i++] = pkt;
	    pkt = strchr (pkt, ' ');
	    if (!pkt)
		break;
	    *pkt++ = 0;
	}

    }
    return i;
}

void
sort_search ()
{
    int i, j;
    struct search ptr;

    for(j=0;j<Search_Size;j++)
    {
	for(i=j;i<Search_Size;i++)
	{
	    if(Search[i].speed < Search[j].speed ||
		    (Search[i].speed == Search[j].speed &&
		     Search[i].bitrate < Search[j].bitrate))
	    {
		memcpy(&ptr,&Search[j],sizeof(ptr));
		memcpy(&Search[j],&Search[i],sizeof(ptr));
		memcpy(&Search[i],&ptr,sizeof(ptr));
	    }
	}
    }
}

void
clear_search ()
{
    int i;
    for(i=0;i<Search_Size;i++)
    {
	if(Search[i].user)
	    free (Search[i].user);
	if(Search[i].file)
	    free (Search[i].file);
    }
}

void user_input (char *s)
{
    short len, type;
    char *p;

    if (!s)
    {
	Quit=1;
	return;
    }
    if(!*s)
	return;
    if (*s == '/')
    {
	s++;
	if (!strncmp ("join", s, 4))
	{
	    s+=4;
	    type = 400;
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
	    while(isspace(*s))
		s++;
	    snprintf (Buf, sizeof (Buf), "FILENAME CONTAINS \"%s\" MAX_RESULTS 100", s);
	    s = Buf;
	    clear_search();
	}
	else if (!strncmp ("part", s, 4))
	{
	    s+=4;
	    type = 401;
	}
	else if (!strncmp("get", s, 3))
	{
	    int i;
	    s += 3;
	    type = 203;
	    i=atoi(s);
	    if (i>0 && i<=Search_Size)
	    {
		snprintf (Buf, sizeof (Buf), "%s \"%s\"", Search[i-1].user,
			Search[i-1].file);
		s=Buf;
	    }
	}
	else if (!strncmp("msg", s, 3))
	{
	    s += 3;
	    type = 205;
	}
	else if (!strncmp("browse", s, 6))
	{
	    s+=6;
	    type=211;
	    clear_search();
	}
	else if (!strncmp("whois", s, 5))
	{
	    s += 5;
	    type = 603;
	}
	else if (!strncmp("list", s, 4))
	{
	    s += 4;
	    type = 617;
	}
	else if (!strncmp("setdataport", s, 11))
	{
	    s += 11;
	    type = 703;
	}
	else if (!strncmp("ping", s, 4))
	{
	    s += 4;
	    type = 751;
	}
	else if (!strncmp("names", s, 5))
	{
	    s += 5;
	    type = 830;
	}
	else if (!strncmp("addhotlist", s, 10))
	{
	    s += 10;
	    type = 207;
	}
	else if (!strncmp("pdown", s, 5))
	{
	    int i;
	    for(i=0;i<Transfer_Size;i++)
	    {
		do_output("-:- Downloads:");
		if(Transfer[i]->download)
		{
		    do_output ("%d \"%s\" %s %d/%d (%d%%) (%d bytes/sec avg)",
			    i + 1,
			    Transfer[i]->filename, Transfer[i]->nick,
			    Transfer[i]->bytes,
			    Transfer[i]->filesize,
			    (100*Transfer[i]->bytes)/Transfer[i]->filesize,
			    Transfer[i]->bytes / (int) (time(0)-Transfer[i]->start));
		}
	    }
	    return;
	}
	else if (!strncmp("speed", s, 5))
	{
	    s += 5;
	    type = 700;
	}
	else
	{
	    do_output("unknown command");
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
    len = p ? strlen (p) : 0;

    write (Fd, &len, 2);
    write (Fd, &type, 2);
    if (len)
	write (Fd, p, len);
    do_output ("sent: len=%d, msg=%d, data=%s", len, type, len ? p : "(empty)");
}

struct xmit *
new_xmit (int fd)
{
    Transfer=realloc(Transfer,sizeof(struct xmit *) * (Transfer_Size+1));
    Transfer[Transfer_Size] = calloc(1,sizeof(struct xmit));
    Transfer[Transfer_Size]->fd = fd;
    Transfer_Size++;
    return Transfer[Transfer_Size-1];
}

int
server_output (void)
{
    short len, msg, bytes = 0, l;
    char *p;
    char *argv[10];
    int argc;

    l = read (Fd, &len, 2);
    if (l != 2)
    {
	do_output ("could not read packet length (%hd)", l);
	return -1;
    }
    l = read (Fd, &msg, 2);
    if (l != 2)
    {
	do_output ("could not read packet type (%hd)", l);
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

    /* handle a ping request */
    if (msg == 751)
    {
	msg = 752; /* pong */
	write (Fd, &len, 2);
	write (Fd, &msg, 2);
	write (Fd, Buf, len);
	do_output("PING from %s", Buf);
    }
    /*search*/
    else if (msg == 201)
    {
	argc=split_line(argv,sizeof(argv)/sizeof(char*),Buf);
	Search = realloc (Search, sizeof (struct search) * (Search_Size + 1));
	Search[Search_Size].file = strdup (argv[0]);
	Search[Search_Size].user = strdup (argv[6]);
	Search[Search_Size].speed = atoi(argv[8]);
	Search[Search_Size].bitrate = atoi(argv[3]);
	Search_Size++;
    }
    else if (msg == 202)
    {
	int i;
	sort_search();
	for(i=0;i<Search_Size;i++)
	{
	    do_output("%d) \"%s\" %s %d %d", i + 1, Search[i].file,
		    Search[i].user, Search[i].bitrate, Search[i].speed);
	}
    }
    else if (msg == 204)
    {
	int newfd;
	struct xmit *xmit;

	do_output("[204] GET accepted");

	/* download ack */
	if(split_line(argv,sizeof(argv)/sizeof(char*),Buf)==6)
	{
	    if (atoi (argv[2]) > 0)
	    {
		struct sockaddr_in sin;

		/* make a connection to the uploader */
		memset(&sin,0,sizeof(sin));
		sin.sin_family=AF_INET;
		sin.sin_port=htons(atoi(argv[2]));
		sin.sin_addr.s_addr=strtoul(argv[1],NULL,10);
		newfd=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
		if(newfd<0)
		{
		    perror("socket");
		    return 0;
		}
		do_output("connecting to %s, port %hd", inet_ntoa(sin.sin_addr),
			ntohs(sin.sin_port));
		if(connect(newfd,(struct sockaddr*)&sin,sizeof(sin))==-1)
		{
		    perror("connect");
		    close(newfd);
		    /*notify the client we could not connect them */
		    snprintf(Buf+4,sizeof(Buf)-4,"%s",argv[0]);
		    len=strlen(argv[0]);
		    msg=626;
		    memcpy(Buf,&len,2);
		    memcpy(Buf+2,&msg,2);
		    write(Fd,Buf,len+4);
		    return 0;
		}
		xmit=new_xmit(newfd);
		xmit->filename = strdup(argv[3]);
		xmit->nick=strdup(argv[0]);
		xmit->download = 1;

		/*notify the server we are downloading */
		msg=218;
		len=0;
		memcpy(Buf,&len,2);
		memcpy(Buf+2,&msg,2);
		write(Fd,Buf,4);

		/* request the file from the uploader */
		write(xmit->fd,"GET",3);
		snprintf(Buf,sizeof(Buf),"%s \"%s\" 0", Nick, xmit->filename);
		write(xmit->fd,Buf,strlen(Buf));

		/* we wait for the client response so we don't block */
	    }
	    else
	    {
		/* uploader is firewalled, send a 500 request */
		do_output("%s is firewalled, sending request...", argv[0]);
		snprintf(Buf+4,sizeof(Buf)-4,"%s \"%s\"", argv[0], argv[3]);
		len=strlen(Buf+4);
		msg=500;
		memcpy(Buf,&len,2);
		memcpy(Buf+2,&msg,2);
		write(Fd,Buf,len+4);
	    }
	}
    }
    /*browse*/
    else if (msg == 212)
    {
	argc=split_line(argv,sizeof(argv)/sizeof(char*),Buf);
	Search = realloc (Search, sizeof (struct search) * (Search_Size + 1));
	Search[Search_Size].user = strdup (argv[0]);
	Search[Search_Size].file = strdup (argv[1]);
	Search_Size++;
	do_output("[212] %d) %s %s %s %s %s", Search_Size,
		argv[0],argv[1],argv[3],argv[4],argv[6]);
    }
    /*motd*/
    else if(msg == 621)
	do_output("[621] %s", Buf);
    else
	do_output ("len=%hd, type=%hd, data=%s", len, msg, Buf);

    return 0;
}

static void
xmit_term (struct xmit *xmit)
{
    int pct = xmit->filesize ? (100*xmit->bytes)/xmit->filesize : 0;
    time_t elapsed = time(0)-xmit->start;
    int rate = elapsed ? xmit->bytes / elapsed : 0;

    close(xmit->fd);
    xmit->fd=-1;
    if(xmit->fp)
	fclose(xmit->fp);
    do_output("Received %d/%d bytes (%d%%) of \"%s\" from %s (%d bytes/sec)",
	    xmit->bytes, xmit->filesize, pct,
	    xmit->filename, xmit->nick, rate);
}

static void
xmit_read (struct xmit *xmit)
{
    char c;
    int n;

    if(xmit->download)
    {
	if(xmit->filesize == 0)
	{
	    /* uploader should send '1' in ASCII */
	    if (read(xmit->fd,&c,1)!=1)
	    {
		close(xmit->fd);
		xmit->fd=-1;
		return;
	    }
	    if (c != '1')
	    {
		do_output ("expected uploader to send `1' as first byte of transfer");
	    }
	    /* need to read the filesize from the client */
	    while(1)
	    {
		n=read(xmit->fd,&c,1);
		if(n==-1)
		{
		    if(errno!=EAGAIN)
		    {
			perror("read");
			xmit_term(xmit);
		    }
		    return;
		}
		else if(n==0)
		{
		    do_output("EOF from %s", xmit->nick);
		    xmit_term(xmit);
		    return;
		}
		if(isdigit(c))
		{
		    xmit->filesize *= 10;
		    xmit->filesize += c - '0';
		}
		else if(isascii(c))
		{
		    fputc(c,stdout);
		    fflush(stdout);
		}
		else
		    break;
	    }

	    xmit->fp = fopen(xmit->filename,"w");
	    if(!xmit->fp)
	    {
		perror("fopen");
		xmit_term(xmit);
		return;
	    }
	    fwrite(&c,1,1,xmit->fp);
	    xmit->bytes=1;
	    do_output("Downloading \"%s\" from %s (%d bytes)", xmit->filename,
		    xmit->nick, xmit->filesize);
	    xmit->start=time(0);
	}
	n=read(xmit->fd,Buf,sizeof(Buf));
	if(n==-1)
	{
	    if(errno!=EAGAIN)
	    {
		perror("read");
		xmit_term(xmit);
	    }
	}
	else if (n==0)
	{
	    do_output("EOF from %s", xmit->nick);
	    xmit_term(xmit);
	}
	else
	{
	    xmit->bytes += n;
	    fwrite(Buf,1,n,xmit->fp);
	    if(xmit->bytes >= xmit->filesize)
	    {
		/* transfer complete */
		xmit_term(xmit);
		fclose(xmit->fp);
	    }
	}
    }
}

static void
xmit_write(struct xmit *xmit)
{
}

static void
usage (void)
{
    printf ("usage: %s [ -rhv ] [ -s SERVER ] [ -p PORT ] [ -u USER ] [ -d DATAPORT ]\n", PACKAGE);
    puts   ("  -d DATAPORT  specify the local data port to listen on");
    puts   ("  -h		display this help message");
    puts   ("  -m META		specify metaserver to connect to");
    puts   ("  -r		auto reconnect to server");
    puts   ("  -s SERVER	connect to SERVER");
    puts   ("  -p PORT	connect to PORT");
    puts   ("  -u USER	log in as USER");
    puts   ("  -v		display version information");
    exit (0);
}

static void
version (void)
{
    printf ("%s %s\n", PACKAGE, VERSION);
    exit (0);
}

int
main (int argc, char **argv)
{
    int i;
    char *server = 0;
    int port = 8888;
    struct sockaddr_in sin;
    fd_set rFds;
    fd_set wFds;
    struct hostent *he;
    int reconnect = 0;
    char *metaserver = "server.napster.com";
    int dataport = 0;
    int maxfd;
    int DataFd;
    size_t sinsize;
    int newfd;

    Nick="kuila0";
    while ((i = getopt (argc, argv, "m:hrs:p:u:vd:")) != -1)
    {
	switch (i)
	{
	    case 'm':
		metaserver = optarg;
		break;
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
		Nick = optarg;
		break;
	    case 'd':
		dataport = atoi(optarg);
		break;
	    case 'v':
		version ();
	    case 'h':
	    default:
		usage ();
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
	he = gethostbyname (metaserver);
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

    do_output ("connecting to %s port %hu...", inet_ntoa (sin.sin_addr), ntohs (sin.sin_port));
    fflush (stdout);

    if (connect (Fd, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
	perror ("connect");

	if (reconnect)
	    goto reconnect;

	exit (1);
    }

    do_output ("connected.");

    /* send the login command */
    snprintf (Buf + 4, sizeof (Buf) - 4, "%s password 0 \"nap v0.9\" 3", Nick);
    Buf[0] = strlen (Buf + 4);
    Buf[1] = 0;
    Buf[2] = 2;
    Buf[3] = 0;
    write (Fd, Buf, Buf[0] + 4);

    FD_ZERO (&rFds);
    FD_ZERO (&wFds);

    rl_callback_handler_install ("spynap> ", user_input);

    while (!Quit)
    {
	FD_SET (0, &rFds);
	FD_SET (Fd, &rFds);
	maxfd=Fd;
	if(dataport!=0)
	{
	    FD_SET (DataFd, &rFds);
	    if(DataFd > maxfd)
		maxfd=DataFd;
	}
	for(i=0;i<Transfer_Size;i++)
	{
	    if(Transfer[i]->fd != -1)
	    {
		if(Transfer[i]->fd > maxfd)
		    maxfd=Transfer[i]->fd;
		if(Transfer[i]->upload)
		    FD_SET(Transfer[i]->fd,&wFds);
		FD_SET(Transfer[i]->fd,&rFds);
	    }
	}
	if (select (maxfd + 1, &rFds, &wFds, 0, 0) == -1)
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
	if (dataport != 0 && FD_ISSET (DataFd, &rFds))
	{
	    /* new data connection */
	    sinsize=sizeof(sin);
	    if((newfd=accept(DataFd,(struct sockaddr *) &sin, &sinsize))!=-1)
	    {
	    }
	}
	for(i=0;i<Transfer_Size;i++)
	{
	    if(Transfer[i]->fd  != -1)
	    {
		if(FD_ISSET(Transfer[i]->fd, &rFds))
		{
		    /* ready to read data */
		    xmit_read(Transfer[i]);
		}
		else if(Transfer[i]->upload && FD_ISSET(Transfer[i]->fd, &wFds))
		{
		    /* ready to write data */
		    xmit_write(Transfer[i]);
		}
	    }
	}
	if(Output)
	{
	    rl_forced_update_display ();
	    Output = 0;
	}
    }

    close (Fd);

    exit (0);
}
