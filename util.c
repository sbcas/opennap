/* Copyright (C) 2000 drscholl@users.sourceforge.net
   This is free software distributed under the terms of the
   GNU Public License.  See the file COPYING for details.

   $Id$

   This file contains various utility functions useful elsewhere in this
   server */

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#ifndef WIN32
#include <unistd.h>
#include <sys/time.h>
#endif
#include <stdlib.h>
#include "md5.h"
#include "opennap.h"
#include "debug.h"

/* no such user */
void
nosuchuser (CONNECTION * con, char *nick)
{
    ASSERT (VALID (con));
    send_cmd (con, MSG_SERVER_NOSUCH, "User %s is not currently online.", nick);
}

void
permission_denied (CONNECTION *con)
{
    send_cmd (con, MSG_SERVER_NOSUCH, "permission denied");
}

/* writes `val' as a two-byte value in little-endian format */
void
set_val (char *d, unsigned short val)
{
    val = BSWAP16 (val);
    memcpy (d, &val, 2);
}

void
send_cmd (CONNECTION *con, unsigned int msgtype, const char *fmt, ...)
{
    va_list ap;
    size_t l;

    va_start (ap, fmt);
    vsnprintf (Buf + 4, sizeof (Buf) - 4, fmt, ap);
    va_end (ap);

    set_tag (Buf, msgtype);
    l = strlen (Buf + 4);
    set_len (Buf, l);
    queue_data (con, Buf, 4 + l);
}

/* adds a pointer to `c' to the list of servers for quick access */
void
add_server (CONNECTION *c)
{
    Servers = REALLOC (Servers, sizeof (CONNECTION *) * (Num_Servers + 1));
    Servers[Num_Servers] = c;
    Num_Servers++;
}

/* send a message to all peer servers.  `con' is the connection the message
   was received from and is used to avoid sending the message back from where
   it originated. */
void
pass_message (CONNECTION *con, char *pkt, size_t pktlen)
{
    int i;

    for (i = 0; i < Num_Servers; i++)
	if (Servers[i] != con)
	    queue_data (Servers[i], pkt, pktlen);
}

/* wrapper for pass_message() */
void
pass_message_args (CONNECTION *con, unsigned int msgtype, const char *fmt, ...)
{
    va_list ap;
    size_t l;

    va_start (ap, fmt);
    vsnprintf (Buf + 4, sizeof (Buf) - 4, fmt, ap);
    va_end (ap);
    set_tag (Buf, msgtype);
    l = strlen (Buf + 4);
    set_len (Buf, l);
    pass_message (con, Buf, 4 + l);
}

/* destroys memory associated with the CHANNEL struct.  this is usually
   not called directly, but in association with the hash_remove() and
   hash_destroy() calls */
void
free_channel (CHANNEL * chan)
{
    ASSERT(validate_channel (chan));
    FREE (chan->name);
    if (chan->topic)
	FREE (chan->topic);
    if (chan->users)
	list_free (chan->users, 0);
    FREE (chan);
}

/* this is like strtok(2), except that all fields are returned as once.  nul
   bytes are written into `pkt' and `template' is updated with pointers to
   each field in `pkt' */
/* returns: number of fields found. */
int
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

int
pop_user (CONNECTION *con, char **pkt, USER **user)
{
    ASSERT (validate_connection (con));
    if (con->class == CLASS_SERVER)
    {
	char *ptr;

	if (**pkt != ':')
	{
	    log ("pop_user(): server message did not contain nick: %s", *pkt);
	    return -1;
	}
	++*pkt;
	ptr = next_arg(pkt);
	*user = hash_lookup (Users, ptr);
	if (!*user)
	{
	    log ("pop_user(): could not find user %s", ptr);
	    return -1;
	}

	/* this should not return a user who is local to us.  if so, it
	   means that some other server has passed us back a message we
	   sent to them */
	if ((*user)->local)
	{
	    log ("pop_user(): fatal error, received server message for local user!");
	    return -1;
	}
    }
    else
    {
	ASSERT (con->class == CLASS_USER);
	ASSERT (con->user != 0);
	*user = con->user;
    }
    return 0;

}

static char hex[] = "0123456789ABCDEF";

void
expand_hex (char *v, int vsize)
{
    int i;

    for (i = vsize - 1; i >= 0; i--)
    {
	v[2 * i + 1] = hex [v[i] & 0xf];
	v[2 * i] = hex [(v[i] >> 4) & 0xf];
    }
}

static int Stale_Random = 1;
static struct md5_ctx Random_Context;

void
init_random (void)
{
#ifdef HAVE_DEV_RANDOM
    int f;
    char seed[8];
#endif

    md5_init_ctx (&Random_Context);
    Stale_Random = 1;
#ifdef HAVE_DEV_RANDOM
    /* seed the random number generate with a better random value */
    if ((f = open ("/dev/random", O_RDONLY)) > 0)
    {
	if (read (f, seed, sizeof(seed)) != sizeof(seed))
	    log ("init_random(): could not read enough random bytes");
	else
	{
	    md5_process_bytes (seed, sizeof (seed), &Random_Context);
	    Stale_Random = 0;
	}
	close (f);
    }
    else
	log ("generate_nonce(): /dev/random: %s", strerror (errno));
#endif
}

void
add_random_bytes (char *s, int ssize)
{
    md5_process_bytes (s, ssize, &Random_Context);
    Stale_Random = 0;
}

void
get_random_bytes (char *d, int dsize)
{
    char buf[16];

    ASSERT (Stale_Random == 0);
    ASSERT (dsize <= 16);
    md5_read_ctx (&Random_Context, buf);
    memcpy (d, buf, dsize);
    md5_process_bytes (buf, 16, &Random_Context);	/* feedback */
}

    /* generate our own nonce value */
char *
generate_nonce (void)
{
    char *nonce;

    nonce = MALLOC (17);
    if (!nonce)
    {
	OUTOFMEMORY ("generate_nonce");
	return 0;
    }
    nonce[16] = 0;

    get_random_bytes (nonce, 8);

    /* expand the binary data into hex for transport */
    expand_hex (nonce, 8);

    return nonce;
}

/* array magic.  this assumes that all pointers are of the same size as
   `char*' */
/* appends `ptr' to the array `list' */
void *
array_add (void *list, int *listsize, void *ptr)
{
    char **plist;

    ASSERT (list == 0 || VALID_LEN (list, *listsize * sizeof (char *)));
    ASSERT (VALID (ptr));
    list = REALLOC (list, sizeof (char *) * (*listsize + 1));
    plist = (char **) list;
    plist[*listsize] = ptr;
    ++*listsize;
    return list;
}

/* removes `ptr' from the array `list'.  note that this does not reclaim
   the space left over, it just shifts down the remaining entries */
void *
array_remove (void *list, int *listsize, void *ptr)
{
    int i;
    char **plist = (char **) list;

    ASSERT (VALID_LEN (list, *listsize * sizeof (char *)));
    ASSERT (VALID (ptr));
    for (i=0;i<*listsize;i++)
    {
	if (ptr == plist[i])
	{
	    if (i < *listsize - 1)
		memmove (&plist[i], &plist[i + 1],
			sizeof (char *) * (*listsize - i - 1));
	    --*listsize;
	    list = REALLOC (list, *listsize * sizeof (char *));
	    break;
	}
    }
    return list;
}

#ifdef DEBUG
int
validate_connection (CONNECTION *con)
{
    ASSERT_RETURN_IF_FAIL (VALID_LEN (con, sizeof (CONNECTION)), 0);
    ASSERT_RETURN_IF_FAIL (con->magic == MAGIC_CONNECTION, 0);
    ASSERT_RETURN_IF_FAIL ((con->class == CLASS_USER) ^ (con->user == 0), 0);
    ASSERT_RETURN_IF_FAIL (VALID (con->host), 0);
    if (con->sendbuf)
	ASSERT_RETURN_IF_FAIL (buffer_validate (con->sendbuf), 0);
    if (con->recvbuf)
	ASSERT_RETURN_IF_FAIL (buffer_validate (con->recvbuf), 0);
    if (ISUSER (con))
	ASSERT_RETURN_IF_FAIL (con->uopt.hotlist == 0 || VALID_LEN (con->uopt.hotlist, sizeof (LIST)), 0);
    return 1;
}

int
validate_user (USER *user)
{
    ASSERT_RETURN_IF_FAIL (VALID_LEN (user, sizeof (USER)), 0);
    ASSERT_RETURN_IF_FAIL (user->magic == MAGIC_USER, 0);
    ASSERT_RETURN_IF_FAIL (VALID (user->nick), 0);
    ASSERT_RETURN_IF_FAIL (VALID (user->clientinfo), 0);
    ASSERT_RETURN_IF_FAIL (user->con == 0 || VALID_LEN (user->con, sizeof (CONNECTION)), 0);
    ASSERT_RETURN_IF_FAIL (user->email == 0 || VALID (user->email), 0);
    ASSERT_RETURN_IF_FAIL (user->channels == 0 || VALID_LEN (user->channels, sizeof (LIST)), 0);
    return 1;
}

int
validate_channel (CHANNEL *chan)
{
    ASSERT_RETURN_IF_FAIL (VALID_LEN (chan, sizeof (CHANNEL)), 0);
    ASSERT_RETURN_IF_FAIL (chan->magic == MAGIC_CHANNEL, 0)
    ASSERT_RETURN_IF_FAIL (VALID (chan->name), 0);
    ASSERT_RETURN_IF_FAIL (chan->users == 0 || VALID_LEN (chan->users, sizeof (LIST)), 0);
    return 1;
}

int
validate_hotlist (HOTLIST *h)
{
    ASSERT_RETURN_IF_FAIL (VALID_LEN (h, sizeof (HOTLIST)), 0);
    ASSERT_RETURN_IF_FAIL (h->magic == MAGIC_HOTLIST, 0);
    ASSERT_RETURN_IF_FAIL (VALID (h->nick), 0);
    ASSERT_RETURN_IF_FAIL (h->users == 0 || VALID_LEN (h->users, sizeof (LIST)), 0);
    return 1;
}
#endif

USER *
new_user (void)
{
    USER *u = CALLOC (1, sizeof (USER));

    if (!u)
    {
	OUTOFMEMORY ("new_user");
	return 0;
    }
#ifdef DEBUG
    u->magic = MAGIC_USER;
#endif
    return u;
}

CHANNEL *
new_channel (void)
{
    CHANNEL *c = CALLOC (1, sizeof (CHANNEL));

    if (!c)
    {
	OUTOFMEMORY ("new_channel");
	return 0;
    }
#ifdef DEBUG
    c->magic = MAGIC_CHANNEL;
#endif
    return c;
}

HOTLIST *
new_hotlist (void)
{
    HOTLIST *h = CALLOC (1, sizeof (HOTLIST));

    if (!h)
    {
	OUTOFMEMORY ("new_hotlist");
	return 0;
    }
#ifdef DEBUG
    h->magic = MAGIC_HOTLIST;
#endif
    return h;
}

CONNECTION *
new_connection (void)
{
    CONNECTION *c = CALLOC (1, sizeof (CONNECTION));

    if (!c)
    {
	OUTOFMEMORY ("new_connection");
	return 0;
    }
#ifdef DEBUG
    c->magic = MAGIC_CONNECTION;
#endif
    return c;
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

/* like next_arg(), except we don't skip over additional whitespace */
char *
next_arg_noskip (char **s)
{
    char *r = *s;
    *s=strchr(r, ' ');
    if(*s)
	*(*s)++=0;
    return r;
}

char *
next_arg (char **s)
{
    char *r = *s;

    if (!r)
	return 0;
    *s = strpbrk (r, " \t\r\n");
    if (*s)
    {
	*(*s)++ = 0;
	while (ISSPACE (**s))
	    ++*s;
	if (!**s)
	    *s = 0;	/* no more arguments */
    }
    return r;
}

char *
strlower (char *s)
{
    char *r = s;
    ASSERT (s != 0);
    while (*s)
    	*s++ = tolower ((unsigned char) *s);
    return r;
}

int
safe_realloc (void **ptr, int bytes)
{
    void *t;

    t = REALLOC (*ptr, bytes);
    if (!t)
	return -1;
    *ptr = t;
    return 0;
}

/* this function sends a command to an arbitrary user without the caller
   needing to know if its a local client or not */
void
send_user (USER *user, int tag, char *fmt, ...)
{
    int len, offset;
    va_list ap;

    if (user->local)
    {
	/* deliver directly */
	va_start(ap, fmt);
	vsnprintf(Buf+4,sizeof(Buf)-4,fmt,ap);
	va_end(ap);
	set_tag(Buf,tag);
	len=strlen(Buf+4);
	set_len(Buf,len);
    }
    else
    {
	/* encapsulate and send to remote server */
#if 0
	log("send_user(): %s is remote, relaying to %s", user->nick,
		user->con->host);
#endif
	snprintf(Buf+4,sizeof(Buf)-4,":%s %s ", Server_Name, user->nick);
	offset=strlen(Buf+4);
	set_tag(Buf,MSG_SERVER_ENCAPSULATED);
	va_start(ap, fmt);
	vsnprintf(Buf+8+offset,sizeof(Buf)-8-offset,fmt,ap);
	va_end(ap);
	set_tag(Buf+4+offset,tag);
	len=strlen(Buf+8+offset);
	set_len(Buf+4+offset,len);
	len += offset + 4;
	set_len(Buf,len);
    }
    queue_data(user->con,Buf,len+4);
}

int
add_client (CONNECTION *cli)
{
    int i;

    if(Max_Clients == Num_Clients)
    {
	/* no space left, allocate more */
	if(safe_realloc((void**)&Clients,sizeof(CONNECTION*)*(Num_Clients+10)))
	{
	    OUTOFMEMORY("add_client");
	    CLOSE(cli->fd);
	    FREE(cli->host);
	    FREE(cli);
	    return -1;
	}
	cli->id = Max_Clients;
	Clients[Max_Clients++] = cli;
	while (Max_Clients < Num_Clients + 10)
	    Clients[Max_Clients++] = 0;
    }
    else
    {
	/* insert this connection into a hole */
	for(i=0;i<Max_Clients;i++)
	    if(!Clients[i])
	    {
		Clients[i]=cli;
		cli->id=i;
		break;
	    }
	ASSERT(i!=Max_Clients);
    }
    Num_Clients++;
    return 0;
}
