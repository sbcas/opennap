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

/* writes `val' as a two-byte value in little-endian format */
void
set_val (char *d, unsigned short val)
{
    val = BSWAP16 (val);
    memcpy (d, &val, 2);
}

/* this is like strtok(2), except that all fields are returned as once.  nul
   bytes are written into `pkt' and `template' is updated with pointers to
   each field in `pkt' */
/* returns: number of fields found. */
int
split_line (char **template, int templatecount, char *pkt)
{
    int i = 0;

    while (ISSPACE (*pkt))
	pkt++;
    while (*pkt && i < templatecount)
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
	    pkt = strpbrk (pkt, " \t\r\n");
	    if (!pkt)
		break;
	    *pkt++ = 0;
	}
	while (ISSPACE (*pkt))
	    pkt++;
    }
    return i;
}

static char hex[] = "0123456789ABCDEF";

void
expand_hex (char *v, int vsize)
{
    int i;

    for (i = vsize - 1; i >= 0; i--)
    {
	v[2 * i + 1] = hex[v[i] & 0xf];
	v[2 * i] = hex[(v[i] >> 4) & 0xf];
    }
}

#if 0
static int Stale_Random = 1;
static struct md5_ctx Random_Context;
#endif

void
init_random (void)
{
#if 0
#ifdef HAVE_DEV_RANDOM
    int f, n;
    char seed[8];
#endif /* HAVE_DEV_RANDOM */

    md5_init_ctx (&Random_Context);
    Stale_Random = 1;
#ifdef HAVE_DEV_RANDOM
    /* seed the random number generate with a better random value */
    if ((f = open ("/dev/random", O_RDONLY)) > 0)
    {
	n = read (f, seed, sizeof (seed));
	if (n > 0)
	{
	    if ((unsigned int) n < sizeof (seed))
		log ("init_random(): only got %d of %d random bytes", n,
		     sizeof (seed));
	    md5_process_bytes (seed, n, &Random_Context);
	    Stale_Random = 0;
	}
	close (f);
    }
    else
	log ("generate_nonce(): /dev/random: %s", strerror (errno));
#endif /* HAVE_DEV_RANDOM */
#else
    ASSERT (Current_Time != 0);
    /* force generation of a different seed if respawning quickly by adding
       the pid of the current process */
    srand (Current_Time + getuid () + getpid ());
#endif
}

#if 0
void
add_random_bytes (char *s, int ssize)
{
    md5_process_bytes (s, ssize, &Random_Context);
    Stale_Random = 0;
}
#endif

void
get_random_bytes (char *d, int dsize)
{
#if 0
    char buf[16];
    ASSERT (Stale_Random == 0);
    ASSERT (dsize <= 16);
    md5_finish_ctx (&Random_Context, buf);
    memcpy (d, buf, dsize);
    md5_process_bytes (buf, 16, &Random_Context);	/* feedback */
#else
    int i = 0, v;

    while (i < dsize)
    {
	v = rand ();
	d[i++] = v & 0xff;
	if(i<dsize)
	    d[i++]=(v>>8)&0xff;
	if(i<dsize)
	    d[i++]=(v>>16)&0xff;
	if(i<dsize)
	    d[i++]=(v>>24)&0xff;
    }
#endif
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

    *s = strchr (r, ' ');
    if (*s)
	*(*s)++ = 0;
    return r;
}

char *
next_arg (char **s)
{
    char *r = *s;

    if (!r)
	return 0;
    while (ISSPACE (*r))
	r++;
    *s = strpbrk (r, " \t\r\n");
    if (*s)
    {
	*(*s)++ = 0;
	while (ISSPACE (**s))
	    ++ * s;
	if (!**s)
	    *s = 0;		/* no more arguments */
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

void
print_args (int ac, char **av)
{
    int i;

    fprintf (stderr, "print_args(): [%d]", ac);
    for (i = 0; i < ac; i++)
	fprintf (stderr, " \"%s\"", av[i]);
    fputc ('\n', stderr);
}

static char alphabet[] =

    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
#define alphabet(c) alphabet[(unsigned int)c]

static int
b64_encode (char *out, int *outsize, char *in, int insize)
{
    unsigned char a, b, c, d;
    char *pout = out;

    while (insize > 0)
    {
	c = d = 0xff;
	a = (*in >> 2) & 0x3f;
	b = (*in & 0x3) << 4;
	in++;
	insize--;
	if (insize)
	{
	    b |= (*in >> 4) & 0xf;
	    c = (*in & 0xf) << 2;
	    in++;
	    insize--;
	    if (insize)
	    {
		c |= (*in >> 6) & 0x3;
		d = *in & 0x3f;
		in++;
		insize--;
	    }
	}
	*out++ = alphabet (a);
	*out++ = alphabet (b);
	if (c != 0xff)
	{
	    *out++ = alphabet (c);
	    if (d != 0xff)
		*out++ = alphabet (d);
	    else
		*out++ = '=';
	}
	else
	{
	    *out++ = '=';
	    *out++ = '=';
	}
    }
    *out = 0;
    *outsize = out - pout;
    return 0;
}

static char b64_lookup[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
};

#define b64_lookup(c) b64_lookup[(unsigned int)c]

static int
b64_decode (char *out, int *outsize, const char *in)
{
    unsigned char a, b, c, d;
    unsigned char b2, b3;
    char *pout = out;

    while (*in)
    {
	a = b64_lookup (*in++);
	b = b64_lookup (*in++);
	*out++ = a << 2 | b >> 4;
	b2 = b << 4;
	if (*in && *in != '=')
	{
	    c = b64_lookup (*in++);
	    b2 |= c >> 2;
	    *out++ = b2;
	    b3 = c << 6;
	    if (*in && *in != '=')
	    {
		d = b64_lookup (*in++);
		b3 |= d;
		*out++ = b3;
	    }
	    else
		break;
	}
	else
	    break;
    }
    *outsize = out - pout;
    return 0;
}

int
check_pass (const char *info, const char *pass)
{
    struct md5_ctx md;
    char hash[16], real[16];
    int realsize;

    ASSERT (info != 0);
    ASSERT (pass != 0);
    if (*info != '1' || *(info + 1) != ',')
	return -1;
    info += 2;
    md5_init_ctx (&md);
    md5_process_bytes (info, 8, &md);
    info += 8;
    if (*info != ',')
	return -1;
    info++;
    md5_process_bytes (pass, strlen (pass), &md);
    md5_finish_ctx (&md, hash);
    realsize = sizeof (real);
    b64_decode (real, &realsize, info);
    ASSERT (realsize == 16);
    if (memcmp (real, hash, 16) == 0)
	return 0;
    return -1;
}

char *
generate_pass (const char *pass)
{
    struct md5_ctx md;
    char hash[16];
    char output[36]; /* 1,xxxxxxxx,xxxxxxxxxxxxxxxxxxxxxxx== */
    int outsize;
    int i;

    ASSERT (pass != 0);
    output[0] = '1';
    output[1] = ',';
    get_random_bytes (output + 2, 8);
    for (i = 0; i < 8; i++)
	output[i + 2] = alphabet[((unsigned int) output[i + 2]) % 64];
    output[10] = ',';
    md5_init_ctx (&md);
    md5_process_bytes (output + 2, 8, &md);
    md5_process_bytes (pass, strlen (pass), &md);
    md5_finish_ctx (&md, hash);
    outsize = sizeof (output) - 11;
    b64_encode (output + 11, &outsize, hash, 16);
    output[sizeof (output) - 3] = 0; /* strip the trailing == */
    return (STRDUP (output));
}

int
form_message (char *d, int dsize, int tag, const char *fmt, ...)
{
    va_list ap;
    int len;

    va_start (ap, fmt);
    vsnprintf (d + 4, dsize - 4, fmt, ap);
    va_end (ap);
    len = strlen (d + 4);
    set_tag (d, tag);
    set_len (d, len);
    return (len + 4);
}
