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

void
init_random (void)
{
    ASSERT (Current_Time != 0);
    /* force generation of a different seed if respawning quickly by adding
       the pid of the current process */
    srand (Current_Time + getuid () + getpid ());
}

void
get_random_bytes (char *d, int dsize)
{
    int i = 0, v;

    while (i < dsize)
    {
	v = rand ();
	d[i++] = v & 0xff;
	if (i < dsize)
	    d[i++] = (v >> 8) & 0xff;
	if (i < dsize)
	    d[i++] = (v >> 16) & 0xff;
	if (i < dsize)
	    d[i++] = (v >> 24) & 0xff;
    }
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

void
log (const char *fmt, ...)
{
    va_list ap;

    va_start (ap, fmt);
    vprintf (fmt, ap);
    va_end (ap);
    fputc ('\n', stdout);
    fflush (stdout);
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
    if (*r == '"')
    {
	r++;
	*s = strchr (r, '"');
    }
    else
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

    printf ("print_args(): [%d]", ac);
    for (i = 0; i < ac; i++)
	printf (" \"%s\"", av[i]);
    fputc ('\n', stdout);
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

static signed char b64_lookup[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
};

/* Stored records contain an eight-character salt and an unpadded MD5 digest. */
int
valid_pass_record (const char *info)
{
    size_t i;
    if (!info || strlen (info) != 33 || info[0] != '1' ||
        info[1] != ',' || info[10] != ',')
        return 0;
    for (i = 2; i < 33; i++)
    {
        unsigned char c = (unsigned char) info[i];
        if (i == 10)
            continue;
        if (c >= sizeof (b64_lookup) || b64_lookup[c] < 0)
            return 0;
    }
    /* The final base64 character contains only two significant bits. */
    return (b64_lookup[(unsigned char) info[32]] & 15) == 0;
}

int
check_pass (const char *info, const char *pass)
{
    struct md5_ctx md;
    unsigned char real[16];
    char hash[16];
    size_t i, out = 0;
    unsigned int bits = 0, nbits = 0;

    if (!pass || !valid_pass_record (info))
        return -1;
    for (i = 11; i < 33; i++)
    {
        bits = (bits << 6) | (unsigned char) b64_lookup[(unsigned char) info[i]];
        nbits += 6;
        if (nbits >= 8)
        {
            nbits -= 8;
            if (out >= sizeof (real))
                return -1;
            real[out++] = (unsigned char) (bits >> nbits);
        }
    }
    if (out != sizeof (real))
        return -1;
    md5_init_ctx (&md);
    md5_process_bytes (info + 2, 8, &md);
    md5_process_bytes (pass, strlen (pass), &md);
    md5_finish_ctx (&md, hash);
    return memcmp (real, hash, sizeof (real)) == 0 ? 0 : -1;
}

char *
generate_pass (const char *pass)
{
    struct md5_ctx md;
    char hash[16];
    char output[36];		/* 1,xxxxxxxx,xxxxxxxxxxxxxxxxxxxxxxx== */
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
    output[sizeof (output) - 3] = 0;	/* strip the trailing == */
    return (STRDUP (output));
}

CHANNEL *
find_channel (LIST * channels, const char *s)
{
    for (; channels; channels = channels->next)
	if (!strcasecmp (((CHANNEL *) channels->data)->name, s))
	    return channels->data;
    return 0;
}

void
free_pointer (void *p)
{
    FREE (p);
}
